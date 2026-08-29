//! `mcpwn audit`: interacting with a live server, under an engagement.
//!
//! Every other command reads. This one **calls tools**, which means it acts on
//! the target: it creates, sends, writes and spends whatever the tools it is
//! allowed to call create, send, write and spend. Pointing it at somebody
//! else's server is not scanning, it is using their infrastructure.
//!
//! Nothing about that is guarded by which binary it lives in, so the guards are
//! in the command itself and there are four of them:
//!
//! * **An engagement file is the only way in.** No `--url`, and no config
//!   discovery: one invocation must never be able to reach every server on a
//!   machine. The file names one target and who authorised it.
//! * **Nothing is called that the engagement did not name.** `tools.allow` is
//!   the scope, it is empty by default, and it is enforced at the wire.
//! * **A tool that takes a command line is skipped** unless the engagement says
//!   otherwise, because probing it runs what it takes.
//! * **Every request and response is written down** as it happens.
//!
//! The rest of `mcpwn` is untouched by this. `scan`, `view` and `discover`
//! still never launch a process and never call a tool.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Subcommand;
use serde_json::json;

use mcpwn::analysis::capabilities::Capability;
use mcpwn::analysis::schema;
use mcpwn::audit::budget::{Budget, Transcript};
use mcpwn::audit::caller::{HttpCaller, StdioCaller, ToolCaller};
use mcpwn::audit::probes::{self, PROBES};
use mcpwn::engagement::{Engagement, DEFAULT_ENGAGEMENT_FILE};
use mcpwn::output::render::TerminalRenderer;
use mcpwn::report::{Report, ScanMeta};
use mcpwn::ToolManifest;

use super::{exit, Cli, Format, SeverityArg};

#[derive(Debug, clap::Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Run the engagement.
    Run(RunArgs),
    /// Print a starter engagement file.
    Init,
    /// List the probes that can be named in an engagement.
    Probes,
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// The engagement file. Defaults to `engagement.toml`.
    ///
    /// This is the only way to name a target. There is deliberately no `--url`.
    #[arg(short, long, value_name = "PATH")]
    pub engagement: Option<PathBuf>,

    /// Where to write the transcript of every request and response.
    #[arg(long, value_name = "PATH", default_value = "mcpwn-audit.jsonl")]
    pub transcript: PathBuf,

    /// Show what would be sent, and send nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    pub format: Format,

    /// Path to the policy file. Defaults to `mcpwn.toml` in the working
    /// directory, and is simply absent if there is none.
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,

    /// Ignore any policy file that would otherwise be picked up.
    #[arg(long, conflicts_with = "policy")]
    pub no_policy: bool,

    /// Lowest severity that makes the run exit non-zero. Overrides the policy
    /// file. Findings below it are still reported.
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<SeverityArg>,
}

pub fn run(cli: &Cli, args: &AuditArgs) -> Result<i32> {
    match &args.action {
        Action::Init => {
            print!("{}", mcpwn::engagement::TEMPLATE);
            Ok(exit::CLEAN)
        }
        Action::Probes => {
            println!("per parameter:");
            for probe in PROBES {
                println!("  {:<20}  {}", probe.id, probe.description);
            }
            println!("\nper target:");
            for (id, description, gated) in probes::TRANSPORT_PROBES {
                let mark = if *gated { " [gated]" } else { "" };
                println!("  {id:<20}  {description}{mark}");
            }
            Ok(exit::CLEAN)
        }
        Action::Run(run) => execute(cli, run),
    }
}

fn execute(cli: &Cli, args: &RunArgs) -> Result<i32> {
    let path = args
        .engagement
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENGAGEMENT_FILE));
    let engagement = Engagement::load(&path)?;

    // Announced before anything is sent. Somebody running this against the
    // wrong target should see it on the way past, not in the transcript
    // afterwards.
    cli.note(&format!(
        "engagement: {} on behalf of {}{}",
        engagement.target,
        engagement.authorized_by,
        engagement
            .reference
            .as_deref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    ));
    eprintln!("  tools in scope: {}", engagement.tools.allow.join(", "));
    // Printed on every run, not buried in a manual: whoever is watching this
    // scroll past should be reminded what it is about to do, and on whose word.
    cli.warn("for authorised testing only: this calls tools on the target");

    let timeout = Duration::from_secs(engagement.limits.timeout_seconds);
    let mut caller: Box<dyn ToolCaller> = if engagement.is_stdio() {
        let command = engagement
            .command()
            .context("the stdio target has no command")?;
        cli.warn(&format!(
            "launching `{command} {}`",
            engagement.args.join(" ")
        ));
        Box::new(
            StdioCaller::spawn(command, &engagement.args, &engagement.env, timeout)
                .map_err(|err| anyhow::anyhow!("{err}"))?,
        )
    } else {
        let headers = mcpwn::enumerate::parse_headers(&engagement.headers)?;
        Box::new(HttpCaller::new(&engagement.target, headers, timeout))
    };

    let tools = caller
        .list_tools()
        .map_err(|err| anyhow::anyhow!("could not list tools: {err}"))?;
    eprintln!("  {} tool(s) advertised", tools.len());

    // The scope is the intersection of what the server has and what the
    // engagement named. Nothing else is touched.
    let in_scope: Vec<ToolManifest> = tools
        .iter()
        .filter(|tool| engagement.allows_tool(&tool.name))
        .cloned()
        .collect();
    for named in &engagement.tools.allow {
        if !tools.iter().any(|t| &t.name == named) {
            cli.warn(&format!(
                "`{named}` is in the engagement but the server does not advertise it"
            ));
        }
    }
    if in_scope.is_empty() {
        anyhow::bail!("none of the tools named in the engagement exist on this server");
    }

    let allowed = engagement.allowed_probes();
    // A gated probe never runs by default: `protocol-fuzz` is the only thing
    // here that can take a target down, so it has to be asked for by name.
    let enabled = |id: &str| match allowed.as_ref() {
        Some(set) => set.contains(id),
        None => !probes::is_gated(id),
    };

    if args.dry_run {
        return plan(&in_scope, &enabled);
    }

    let mut transcript = Transcript::open(&args.transcript, &engagement)?;
    let mut budget = Budget::new(
        engagement.limits.max_requests,
        engagement.limits.rate_per_second,
    );
    let nonce = nonce();
    let mut findings = Vec::new();
    let mut stopped = None;

    for tool in &in_scope {
        // A tool the static analysis reads as command execution is not probed
        // unless the engagement says so: probing it runs what it takes.
        if let Some(reason) = dangerous(tool) {
            if !engagement.tools.allow_dangerous {
                cli.warn(&format!(
                    "skipping `{}`: {reason}. Set `tools.allow_dangerous` to include it.",
                    tool.name
                ));
                continue;
            }
        }

        let params = tool
            .input_schema
            .as_ref()
            .map(|s| schema::flatten(s).params)
            .unwrap_or_default();

        let mut spend = |exchange: &probes::Exchange| -> std::result::Result<(), String> {
            budget.take()?;
            transcript
                .write(json!({
                    "kind": "call",
                    "tool": exchange.tool,
                    "parameter": exchange.param,
                    "probe": exchange.probe,
                    "payload": exchange.payload,
                    "outcome": match &exchange.outcome {
                        Ok(outcome) => json!({
                            "ok": true,
                            "is_error": outcome.is_error,
                            "duration_ms": outcome.duration.as_millis() as u64,
                            "response": outcome.raw,
                        }),
                        Err(err) => json!({ "ok": false, "error": err }),
                    },
                }))
                .map_err(|err| err.to_string())
        };

        match probes::run_tool(
            caller.as_mut(),
            &engagement.target,
            tool,
            &params,
            &enabled,
            &nonce,
            &mut spend,
        ) {
            Ok(found) => findings.extend(found),
            Err(err) => {
                stopped = Some(err);
                break;
            }
        }
    }

    if stopped.is_none() {
        let mut spend = |exchange: &probes::Exchange| -> std::result::Result<(), String> {
            budget.take()?;
            transcript
                .write(json!({
                    "kind": "call",
                    "tool": exchange.tool,
                    "parameter": exchange.param,
                    "probe": exchange.probe,
                    "payload": exchange.payload,
                    "outcome": match &exchange.outcome {
                        Ok(outcome) => json!({
                            "ok": true,
                            "is_error": outcome.is_error,
                            "duration_ms": outcome.duration.as_millis() as u64,
                            "response": outcome.raw,
                        }),
                        Err(err) => json!({ "ok": false, "error": err }),
                    },
                }))
                .map_err(|err| err.to_string())
        };
        match probes::run_transport(caller.as_mut(), &engagement, &enabled, &nonce, &mut spend) {
            Ok(found) => findings.extend(found),
            Err(err) => stopped = Some(err),
        }
    }

    let mut meta = ScanMeta::new(Some(engagement.target.clone()));
    meta.servers = 1;
    meta.tools = in_scope.len();
    let mut report = Report::new(meta);
    report.extend(findings);
    report.sort();

    // The same policy file the scanner reads: a rule accepted for a server is
    // accepted whichever command found it.
    let policy = cli.read_policy(args.policy.as_deref(), args.no_policy)?;
    let effect = policy.apply(&mut report);
    let fail_on = args
        .fail_on
        .map(Into::into)
        .unwrap_or_else(|| policy.fail_on());

    let mut stdout = io::stdout().lock();
    match args.format {
        Format::Terminal => {
            TerminalRenderer::new()
                .color(cli.use_color())
                .verbose(cli.verbose)
                .render(&report, &mut stdout)?;
        }
        // The engagement travels with the findings: a report that does not say
        // what was authorised, against what, and where the transcript is, is
        // not a deliverable.
        Format::Json => {
            let payload = json!({
                "report": report,
                "engagement": {
                    "target": engagement.target,
                    "authorized_by": engagement.authorized_by,
                    "reference": engagement.reference,
                    "tools_in_scope": in_scope.iter().map(|t| &t.name).collect::<Vec<_>>(),
                },
                "transcript": transcript.path(),
                "calls_sent": budget.spent(),
            });
            writeln!(stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
        }
        Format::Sarif => writeln!(
            stdout,
            "{}",
            mcpwn::output::sarif::to_sarif_string(&report)?
        )?,
    }
    stdout.flush()?;

    eprintln!(
        "\n{} call(s) sent, transcript at {}",
        budget.spent(),
        transcript.path()
    );
    cli.report_policy_effect(&effect);
    if let Some(reason) = stopped {
        cli.warn(&reason);
    }

    Ok(if report.max_severity().is_some_and(|s| s >= fail_on) {
        exit::FINDINGS
    } else {
        exit::CLEAN
    })
}

/// Show the plan without sending anything.
fn plan(tools: &[ToolManifest], enabled: &dyn Fn(&str) -> bool) -> Result<i32> {
    println!("dry run: nothing is sent");

    let transport: Vec<&str> = probes::TRANSPORT_PROBES
        .iter()
        .filter(|(id, _, _)| enabled(id))
        .map(|(id, _, _)| *id)
        .collect();
    println!(
        "\n  (transport)\n    {}",
        if transport.is_empty() {
            "no transport probe enabled".to_owned()
        } else {
            transport.join(", ")
        }
    );

    for tool in tools {
        println!("\n  {}", tool.name);
        if let Some(reason) = dangerous(tool) {
            println!("    would be skipped: {reason}");
        }
        let params = tool
            .input_schema
            .as_ref()
            .map(|s| schema::flatten(s).params)
            .unwrap_or_default();
        for probe in PROBES.iter().filter(|p| enabled(p.id)) {
            let targets: Vec<&str> = params
                .iter()
                .filter(|p| probes::would_target(probe, p))
                .map(|p| p.path.as_str())
                .collect();
            if !targets.is_empty() {
                println!("    {:<20} -> {}", probe.id, targets.join(", "));
            }
        }
    }
    Ok(exit::CLEAN)
}

/// Why a tool should not be probed without an explicit say-so.
fn dangerous(tool: &ToolManifest) -> Option<&'static str> {
    let input_schema = tool.input_schema.as_ref()?;
    for param in schema::flatten(input_schema).iter() {
        for capability in mcpwn::analysis::capabilities::capabilities_of(param) {
            match capability {
                Capability::CommandExecution => {
                    return Some("it takes a command line, so a probe would run it")
                }
                Capability::CodeEvaluation => {
                    return Some("it evaluates code, so a probe would execute it")
                }
                _ => {}
            }
        }
    }
    None
}

/// A per-run marker no response can contain by chance.
fn nonce() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), now)
}
