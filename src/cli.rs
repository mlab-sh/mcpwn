//! Argument parsing and command dispatch. Binary-only: the library knows
//! nothing about it.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;

use mcpwn::output::{inventory::InventoryRenderer, render::TerminalRenderer, sarif};
use mcpwn::{
    discovery, enumerate, loading, Analyzer, AnalyzerConfig, DiscoveredConfig, EnumeratedServer,
    LoadedConfig, Report, StaticEnumerator,
};

/// Static, offline security scanner for MCP servers.
#[derive(Debug, Parser)]
#[command(name = "mcpwn", version, about, long_about = None)]
pub struct Cli {
    /// Print per-item detail (findings: message and evidence; discover: servers).
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
    /// Scan MCP server configs for dangerous tool definitions.
    Scan(ScanArgs),
    /// Explain a finding id, e.g. `mcpwn explain MCPWN-TP-001`.
    Explain {
        /// The rule id to explain.
        id: String,
    },
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

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    pub format: Format,
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
            Command::Scan(args) => self.scan(args),
            Command::Explain { id } => Self::explain(id),
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

    fn scan(&self, args: &ScanArgs) -> Result<i32> {
        let source = if args.url.is_empty() {
            Source::Configs(&args.paths)
        } else {
            Source::Endpoints(&args.url)
        };
        let headers = enumerate::parse_headers(&args.headers)?;
        let (loaded, enumerated) = collect(&source, headers)?;
        let servers: Vec<_> = enumerated.iter().map(|e| e.server.clone()).collect();

        let analyzer = Analyzer::with_config(AnalyzerConfig {
            target: Some(source.describe()),
            skip_flow: false,
        });
        let report = analyzer.analyze(&servers);

        let mut stdout = io::stdout().lock();
        self.emit(&report, args.format, &mut stdout)?;
        if args.format == Format::Terminal {
            InventoryRenderer::new()
                .color(self.use_color())
                .verbose(self.verbose)
                .render_servers(&enumerated, &mut stdout)?;
        }
        stdout.flush()?;

        self.emit_warnings(&loaded, &enumerated);

        Ok(if report.is_empty() {
            exit::CLEAN
        } else {
            exit::FINDINGS
        })
    }

    fn emit<W: Write>(&self, report: &Report, format: Format, out: &mut W) -> Result<()> {
        match format {
            Format::Terminal => {
                TerminalRenderer::new()
                    .color(self.use_color())
                    .verbose(self.verbose)
                    .render(report, out)?;
                writeln!(
                    out,
                    "\nnote: configs are discovered and loaded, but tool enumeration and the \
                     detection modules are not implemented yet."
                )?;
            }
            Format::Sarif => writeln!(out, "{}", sarif::to_sarif_string(report)?)?,
            Format::Json => writeln!(out, "{}", report.to_json()?)?,
        }
        Ok(())
    }

    fn explain(id: &str) -> Result<i32> {
        match mcpwn::output::render::explain(id) {
            Some(text) => {
                println!("{text}");
                Ok(exit::CLEAN)
            }
            None => {
                eprintln!("explain: not implemented yet (no entry for `{id}`)");
                Ok(exit::ERROR)
            }
        }
    }

    /// Unreadable, invalid or not-yet-parseable files are reported on stderr and
    /// never abort the run.
    fn emit_warnings(&self, loaded: &[LoadedConfig], servers: &[EnumeratedServer]) {
        let color = self.use_color_stderr();
        let warnings = mcpwn::output::inventory::warnings(loaded)
            .into_iter()
            .chain(mcpwn::output::inventory::enumeration_warnings(servers));
        for warning in warnings {
            if color {
                eprintln!("{} {warning}", "warning:".yellow().bold());
            } else {
                eprintln!("warning: {warning}");
            }
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
/// never launched. Both sources reach the *same* `enumerate_all` call — a
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
