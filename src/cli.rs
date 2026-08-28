//! Argument parsing and command dispatch. Binary-only: the library knows
//! nothing about it.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;

use mcpwn::analysis::registry::Registry;
use mcpwn::analysis::rugpull::RugPullCheck;
use mcpwn::explain;
use mcpwn::lock::{self, Lock, ServerId, ToolChange, DEFAULT_LOCK_FILE};
use mcpwn::output::{
    explain::ExplainRenderer, inventory::InventoryRenderer, render::TerminalRenderer, sarif,
};
use mcpwn::policy::{Policy, DEFAULT_POLICY_FILE};
use mcpwn::{
    discovery, enumerate, loading, Analyzer, AnalyzerConfig, DiscoveredConfig, EnumeratedServer,
    LoadedConfig, Report, StaticEnumerator,
};

/// Static, offline security scanner for MCP servers.
#[derive(Debug, Parser)]
#[command(name = "mcpwn", version, about, long_about = None)]
pub struct Cli {
    /// Print more detail: finding messages and evidence for `scan`, the tools
    /// of each server for `discover`, the raw input schemas for `view`.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Never emit ANSI colour (also honoured: a non-tty stdout).
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List the MCP configuration files on this machine, without analysing them.
    Discover(DiscoverArgs),
    /// Show everything a server exposes: its tools, their descriptions and
    /// their parameters. No analysis.
    View(ViewArgs),
    /// Scan MCP server configs for dangerous tool definitions.
    Scan(ScanArgs),
    /// Explain a rule id, e.g. `mcpwn explain MCPWN-CAP-001`. Without one,
    /// lists every rule mcpwn can emit.
    Explain(ExplainArgs),
    /// Compare two lockfiles, for reviewing a change to `mcp.lock`.
    Diff(DiffArgs),
    /// Print a starter `mcpwn.toml` policy file.
    InitPolicy,
}

#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// The lockfile as it was.
    #[arg(value_name = "BEFORE")]
    pub before: PathBuf,
    /// The lockfile as it is now.
    #[arg(value_name = "AFTER")]
    pub after: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct DiscoverArgs {
    /// Project directory (or a single config file) to search. Without one,
    /// the well-known per-user locations are searched instead.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = InventoryFormat::Terminal)]
    pub format: InventoryFormat,
}

#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// The rule id. The `MCPWN-` prefix is optional and case does not matter.
    #[arg(value_name = "ID")]
    pub id: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = InventoryFormat::Terminal)]
    pub format: InventoryFormat,
}

#[derive(Debug, clap::Args)]
pub struct ViewArgs {
    /// Project directory (or a single config file) to read. Without one, the
    /// well-known per-user locations are used instead.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Read one MCP endpoint directly. Repeatable. Cannot be combined with a PATH.
    #[arg(long, value_name = "URL", conflicts_with = "paths")]
    pub url: Vec<String>,

    /// Extra HTTP header, curl-style. Repeatable.
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,

    /// Show only tools whose name contains this.
    #[arg(short, long, value_name = "SUBSTRING")]
    pub tool: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = InventoryFormat::Terminal)]
    pub format: InventoryFormat,
}

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Project directory (or a single config file) to scan. Without one, the
    /// well-known per-user locations are scanned instead.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Scan an MCP endpoint directly, skipping config discovery entirely.
    /// Repeatable. Cannot be combined with a PATH.
    #[arg(long, value_name = "URL", conflicts_with = "paths")]
    pub url: Vec<String>,

    /// Extra HTTP header, curl-style, sent to every HTTP server in the run.
    /// Repeatable.
    ///
    /// Use it to reach an authenticated endpoint:
    /// `-H "Authorization: Bearer $TOKEN"`.
    ///
    /// Note that a secret written on the command line is visible to every
    /// process on the machine (`ps`) and lands in your shell history. Prefer
    /// expanding it from an environment variable, and prefix the command with a
    /// space if your shell is set up to skip those.
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,

    /// Path to the lockfile used for rug-pull detection.
    ///
    /// When it exists it is compared against, and differences are reported.
    /// Defaults to `mcp.lock` in the working directory.
    #[arg(long, value_name = "PATH")]
    pub lock: Option<PathBuf>,

    /// Write the lockfile to establish a baseline. Refuses to overwrite an
    /// existing one: use --update-lock for that.
    #[arg(long, conflicts_with = "update_lock")]
    pub write_lock: bool,

    /// Rewrite the lockfile with what this scan found, after reviewing the
    /// reported changes. A plain scan never writes the lock: refreshing the
    /// baseline automatically would erase the mutation it just detected.
    #[arg(long)]
    pub update_lock: bool,

    /// Path to the policy file. Defaults to `mcpwn.toml` in the working
    /// directory, and is simply absent if there is none.
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,

    /// Ignore any policy file that would otherwise be picked up.
    #[arg(long, conflicts_with = "policy")]
    pub no_policy: bool,

    /// Lowest severity that makes the scan exit non-zero. Overrides the policy
    /// file. Findings below it are still reported.
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<SeverityArg>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    pub format: Format,
}

/// Severity as a command-line value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for mcpwn::Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Critical => mcpwn::Severity::Critical,
            SeverityArg::High => mcpwn::Severity::High,
            SeverityArg::Medium => mcpwn::Severity::Medium,
            SeverityArg::Low => mcpwn::Severity::Low,
            SeverityArg::Info => mcpwn::Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Format {
    /// Human-readable, colourised, grouped by severity.
    Terminal,
    /// SARIF 2.1.0, for CI and code scanning.
    Sarif,
    /// The raw report as JSON.
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum InventoryFormat {
    /// Human-readable table.
    Terminal,
    /// The raw inventory as JSON.
    Json,
}

/// Process exit codes.
pub mod exit {
    /// Command completed, nothing to report.
    pub const CLEAN: i32 = 0;
    /// Scan completed with findings.
    pub const FINDINGS: i32 = 1;
    /// Something went wrong.
    pub const ERROR: i32 = 2;
}

impl Cli {
    /// Run the selected command; returns the process exit code.
    pub fn run(&self) -> Result<i32> {
        match &self.command {
            Command::Discover(args) => self.discover(args),
            Command::View(args) => self.view(args),
            Command::Scan(args) => self.scan(args),
            Command::Explain(args) => self.explain(args),
            Command::Diff(args) => self.diff(args),
            Command::InitPolicy => {
                print!("{}", mcpwn::policy::TEMPLATE);
                Ok(exit::CLEAN)
            }
        }
    }

    /// `discover` is its own subcommand rather than a `scan --discover-only`
    /// flag: it answers a different question ("did mcpwn even see my config?"),
    /// its output is an inventory rather than a security report, and it never
    /// returns the findings exit code. `scan` reuses the exact same two steps.
    fn discover(&self, args: &DiscoverArgs) -> Result<i32> {
        let (loaded, servers) = collect(&Source::Configs(&args.paths), Vec::new())?;

        let mut stdout = io::stdout().lock();
        match args.format {
            InventoryFormat::Terminal => {
                let renderer = InventoryRenderer::new()
                    .color(self.use_color())
                    .verbose(self.verbose);
                renderer.render(&loaded, &mut stdout)?;
                renderer.render_servers(&servers, &mut stdout)?;
            }
            InventoryFormat::Json => {
                let payload = serde_json::json!({ "configs": loaded, "servers": servers });
                writeln!(stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
            }
        }
        stdout.flush()?;

        self.emit_warnings(&loaded, &servers);
        Ok(exit::CLEAN)
    }

    /// `view` shares discovery, loading and enumeration with `scan`; only the
    /// rendering differs. Nothing is analysed and nothing can fail the run.
    fn view(&self, args: &ViewArgs) -> Result<i32> {
        let source = if args.url.is_empty() {
            Source::Configs(&args.paths)
        } else {
            Source::Endpoints(&args.url)
        };
        let headers = enumerate::parse_headers(&args.headers)?;
        let (loaded, enumerated) = collect(&source, headers)?;

        let mut stdout = io::stdout().lock();
        match args.format {
            InventoryFormat::Terminal => {
                mcpwn::output::view::ViewRenderer::new()
                    .color(self.use_color())
                    .verbose(self.verbose)
                    .filter(args.tool.clone())
                    .render(&enumerated, &mut stdout)?;
            }
            InventoryFormat::Json => {
                writeln!(stdout, "{}", serde_json::to_string_pretty(&enumerated)?)?;
            }
        }
        stdout.flush()?;

        self.emit_warnings(&loaded, &enumerated);
        Ok(exit::CLEAN)
    }

    fn scan(&self, args: &ScanArgs) -> Result<i32> {
        let source = if args.url.is_empty() {
            Source::Configs(&args.paths)
        } else {
            Source::Endpoints(&args.url)
        };
        let headers = enumerate::parse_headers(&args.headers)?;
        let (loaded, enumerated) = collect(&source, headers)?;
        let servers: Vec<_> = enumerated.iter().map(|e| e.server.clone()).collect();

        // Only servers actually enumerated take part in lock comparison: an
        // unreachable one has an empty tool list, which must not read as "every
        // tool was removed", nor overwrite its baseline on --update-lock.
        let observed: Vec<(ServerId, Vec<mcpwn::ToolManifest>)> = enumerated
            .iter()
            .filter(|e| e.outcome.is_enumerated())
            .map(|e| (ServerId::from_manifest(&e.server), e.server.tools.clone()))
            .collect();

        let lock_path = args
            .lock
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_FILE));
        let existing = self.read_lock(&lock_path, args.lock.is_some());

        let mut registry = Registry::builtin();
        if let Some(lock) = existing.clone() {
            registry = registry.with_global_check(RugPullCheck::new(
                lock,
                observed.iter().map(|(id, _)| id.clone()).collect(),
            ));
        }

        let analyzer = Analyzer::with_config(AnalyzerConfig {
            target: Some(source.describe()),
            skip_global: false,
        })
        .with_registry(registry);
        let mut report = analyzer.analyze(&servers);

        let policy = self.read_policy(args)?;
        let effect = policy.apply(&mut report);
        let fail_on = args
            .fail_on
            .map(Into::into)
            .unwrap_or_else(|| policy.fail_on());

        let mut stdout = io::stdout().lock();
        self.emit_report(&report, &enumerated, args.format, &mut stdout)?;
        if args.format == Format::Terminal {
            InventoryRenderer::new()
                .color(self.use_color())
                .verbose(self.verbose)
                .render_servers(&enumerated, &mut stdout)?;
        }
        stdout.flush()?;

        self.emit_warnings(&loaded, &enumerated);
        // What the policy removed is said out loud: silently dropped findings
        // are how a policy file rots into a blindfold.
        if !effect.is_empty() {
            self.warn(&format!(
                "policy applied: {} finding(s) suppressed, {} rule(s) disabled, {} re-tuned",
                effect.suppressed, effect.disabled, effect.retuned
            ));
        }
        self.write_lock(args, &lock_path, existing, &observed)?;

        let failing = report.max_severity().is_some_and(|worst| worst >= fail_on);
        Ok(if failing { exit::FINDINGS } else { exit::CLEAN })
    }

    /// Load the policy, unless told not to.
    fn read_policy(&self, args: &ScanArgs) -> Result<Policy> {
        if args.no_policy {
            return Ok(Policy::default());
        }
        let explicit = args.policy.is_some();
        let path = args
            .policy
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_FILE));

        match Policy::load(&path) {
            Ok(Some(policy)) => Ok(policy),
            Ok(None) => {
                if explicit {
                    anyhow::bail!("{}: no such policy file", path.display());
                }
                Ok(Policy::default())
            }
            // A broken policy is a hard error, unlike a broken lockfile: a
            // typo that silently disables a rule is exactly the failure mode
            // the file exists to avoid.
            Err(err) => Err(err.into()),
        }
    }

    /// `mcpwn diff before.lock after.lock`.
    fn diff(&self, args: &DiffArgs) -> Result<i32> {
        let load = |path: &Path| -> Result<Lock> {
            Lock::load(path)?.ok_or_else(|| anyhow::anyhow!("{}: no such lockfile", path.display()))
        };
        let before = load(&args.before)?;
        let after = load(&args.after)?;

        let mut stdout = io::stdout().lock();
        let mut changed = false;

        let ids: std::collections::BTreeSet<&mcpwn::ServerId> = before
            .servers
            .iter()
            .chain(after.servers.iter())
            .map(|s| &s.id)
            .collect();

        for id in ids {
            match (before.server(id), after.server(id)) {
                (Some(_), None) => {
                    changed = true;
                    writeln!(stdout, "- server removed  {id}")?;
                }
                (None, Some(server)) => {
                    changed = true;
                    writeln!(
                        stdout,
                        "+ server added    {id} ({} tool(s))",
                        server.tools.len()
                    )?;
                }
                (Some(old), Some(new)) => {
                    // Reuse the comparison the check itself uses, so `diff` and
                    // a scan can never disagree about what changed.
                    for change in Lock::compare_locked(old, new) {
                        changed = true;
                        match change {
                            ToolChange::Mutated { name, fields, .. } => writeln!(
                                stdout,
                                "~ tool changed    {id}::{name} ({})",
                                if fields.is_empty() {
                                    "content".to_owned()
                                } else {
                                    fields.join(", ")
                                }
                            )?,
                            ToolChange::Added { name } => {
                                writeln!(stdout, "+ tool added      {id}::{name}")?
                            }
                            ToolChange::Removed { name } => {
                                writeln!(stdout, "- tool removed    {id}::{name}")?
                            }
                        }
                    }
                }
                (None, None) => {}
            }
        }

        if !changed {
            writeln!(stdout, "the two lockfiles are equivalent")?;
        }
        stdout.flush()?;
        Ok(if changed { exit::FINDINGS } else { exit::CLEAN })
    }

    fn emit_report<W: Write>(
        &self,
        report: &Report,
        enumerated: &[EnumeratedServer],
        format: Format,
        out: &mut W,
    ) -> Result<()> {
        if format == Format::Json {
            // The enumerated tools travel with the report: without them there
            // is no machine-readable way to see what a `--url` scan actually
            // found.
            let payload = serde_json::json!({ "report": report, "servers": enumerated });
            writeln!(out, "{}", serde_json::to_string_pretty(&payload)?)?;
            return Ok(());
        }
        self.emit(report, format, out)
    }

    fn emit<W: Write>(&self, report: &Report, format: Format, out: &mut W) -> Result<()> {
        match format {
            Format::Terminal => {
                TerminalRenderer::new()
                    .color(self.use_color())
                    .verbose(self.verbose)
                    .render(report, out)?;
            }
            Format::Sarif => writeln!(out, "{}", sarif::to_sarif_string(report)?)?,
            // Handled by `emit_report`, which attaches the enumerated tools.
            Format::Json => writeln!(out, "{}", report.to_json()?)?,
        }
        Ok(())
    }

    fn explain(&self, args: &ExplainArgs) -> Result<i32> {
        let renderer = ExplainRenderer::new().color(self.use_color());
        let mut stdout = io::stdout().lock();

        let Some(id) = args.id.as_deref() else {
            // No id: the catalogue, so the ids are discoverable at all.
            match args.format {
                InventoryFormat::Terminal => renderer.render_index(explain::all(), &mut stdout)?,
                InventoryFormat::Json => {
                    writeln!(stdout, "{}", serde_json::to_string_pretty(explain::all())?)?
                }
            }
            stdout.flush()?;
            return Ok(exit::CLEAN);
        };

        let Some(rule) = explain::lookup(id) else {
            let known: Vec<&str> = explain::all().iter().map(|r| r.id).collect();
            anyhow::bail!(
                "no rule `{id}`. Known rules: {}. Run `mcpwn explain` to list them with a summary.",
                known.join(", ")
            );
        };

        match args.format {
            InventoryFormat::Terminal => renderer.render(rule, &mut stdout)?,
            InventoryFormat::Json => writeln!(stdout, "{}", serde_json::to_string_pretty(rule)?)?,
        }
        stdout.flush()?;
        Ok(exit::CLEAN)
    }

    /// Load the lockfile, if there is a usable one.
    ///
    /// A corrupt or future-versioned lock is a warning, never a failure: the
    /// rest of the scan is still worth running, and refusing to start would
    /// leave the user with no output at all.
    fn read_lock(&self, path: &Path, explicit: bool) -> Option<Lock> {
        match Lock::load(path) {
            Ok(Some(lock)) => Some(lock),
            Ok(None) => {
                if explicit {
                    self.warn(&format!(
                        "{}: no lockfile there yet; run with --write-lock to create one",
                        path.display()
                    ));
                }
                None
            }
            Err(err) => {
                self.warn(&format!(
                    "{err}. Continuing without rug-pull detection; delete the file and re-run                      with --write-lock, or fix it by hand"
                ));
                None
            }
        }
    }

    /// Write the lock, but only when explicitly asked to.
    fn write_lock(
        &self,
        args: &ScanArgs,
        path: &Path,
        existing: Option<Lock>,
        observed: &[(ServerId, Vec<mcpwn::ToolManifest>)],
    ) -> Result<()> {
        if !args.write_lock && !args.update_lock {
            return Ok(());
        }
        if args.write_lock && existing.is_some() {
            anyhow::bail!(
                "{} already exists. Review the reported changes, then re-run with --update-lock                  to accept them.",
                path.display()
            );
        }
        if observed.is_empty() {
            self.warn("no server was enumerated, so the lockfile was left untouched");
            return Ok(());
        }

        let updated = existing
            .unwrap_or_default()
            .updated_from(observed, &lock::now_iso8601());
        updated.save(path)?;

        let tools: usize = observed.iter().map(|(_, t)| t.len()).sum();
        eprintln!(
            "lockfile {} written: {} server(s), {tools} tool(s)",
            path.display(),
            observed.len()
        );
        Ok(())
    }

    fn warn(&self, message: &str) {
        if self.use_color_stderr() {
            eprintln!("{} {message}", "warning:".yellow().bold());
        } else {
            eprintln!("warning: {message}");
        }
    }

    /// Unreadable, invalid or not-yet-parseable files are reported on stderr and
    /// never abort the run.
    fn emit_warnings(&self, loaded: &[LoadedConfig], servers: &[EnumeratedServer]) {
        let warnings = mcpwn::output::inventory::warnings(loaded)
            .into_iter()
            .chain(mcpwn::output::inventory::enumeration_warnings(servers));
        for warning in warnings {
            self.warn(&warning);
        }
    }

    fn use_color(&self) -> bool {
        !self.no_color && io::stdout().is_terminal()
    }

    fn use_color_stderr(&self) -> bool {
        !self.no_color && io::stderr().is_terminal()
    }
}

/// Where the servers to inspect come from.
///
/// The two variants diverge only in how the server list is obtained; both
/// converge on the same `Vec<ServerManifest>` and the same enumerator.
enum Source<'a> {
    /// Discover and load config files (no path = the global locations).
    Configs(&'a [PathBuf]),
    /// Endpoints named on the command line; discovery is skipped entirely.
    Endpoints(&'a [String]),
}

impl Source<'_> {
    fn describe(&self) -> String {
        match self {
            Source::Configs([]) => "(global MCP config locations)".to_owned(),
            Source::Configs(paths) => paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            Source::Endpoints(urls) => urls.join(", "),
        }
    }
}

/// Resolve a source into servers, then statically enumerate them.
///
/// Enumeration is static-only: HTTP servers are queried, stdio servers are
/// never launched. Both sources reach the *same* `enumerate_all` call; a
/// direct endpoint is turned into an ordinary `ServerManifest` first, so there
/// is one enumeration path, not two.
fn collect(
    source: &Source<'_>,
    headers: Vec<(String, String)>,
) -> Result<(Vec<LoadedConfig>, Vec<EnumeratedServer>)> {
    let (loaded, servers) = match source {
        Source::Configs(paths) => {
            let configs: Vec<DiscoveredConfig> = if paths.is_empty() {
                discovery::discover_global()
            } else {
                let mut found: Vec<DiscoveredConfig> = paths
                    .iter()
                    .flat_map(|p| discovery::discover_project(Path::new(p)))
                    .collect();
                found.sort();
                found.dedup_by(|a, b| a.path == b.path);
                found
            };
            let loaded = loading::load_all(&configs);
            let servers = loading::servers_of(&loaded);
            (loaded, servers)
        }
        Source::Endpoints(urls) => {
            // Validate every URL before touching the network, so a typo in the
            // third one does not surface after two requests have gone out.
            let servers = urls
                .iter()
                .map(|url| enumerate::server_from_url(url))
                .collect::<mcpwn::Result<Vec<_>>>()?;
            (Vec::new(), servers)
        }
    };

    let enumerator = StaticEnumerator::new().headers(headers);
    Ok((loaded, enumerator.enumerate_all(servers)))
}
