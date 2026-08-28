//! Argument parsing and command dispatch. Binary-only: the library knows
//! nothing about it.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;

use mcpwn::output::{inventory::InventoryRenderer, render::TerminalRenderer, sarif};
use mcpwn::{discovery, loading, Analyzer, AnalyzerConfig, DiscoveredConfig, LoadedConfig, Report};

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
        let loaded = collect(&args.paths);

        let mut stdout = io::stdout().lock();
        match args.format {
            InventoryFormat::Terminal => {
                InventoryRenderer::new()
                    .color(self.use_color())
                    .verbose(self.verbose)
                    .render(&loaded, &mut stdout)?;
            }
            InventoryFormat::Json => {
                writeln!(stdout, "{}", serde_json::to_string_pretty(&loaded)?)?;
            }
        }
        stdout.flush()?;

        self.emit_warnings(&loaded);
        Ok(exit::CLEAN)
    }

    fn scan(&self, args: &ScanArgs) -> Result<i32> {
        let loaded = collect(&args.paths);
        let servers = loading::servers_of(&loaded);

        let analyzer = Analyzer::with_config(AnalyzerConfig {
            target: Some(describe_target(&args.paths)),
            skip_flow: false,
        });
        let report = analyzer.analyze(&servers);

        let mut stdout = io::stdout().lock();
        self.emit(&report, args.format, &mut stdout)?;
        stdout.flush()?;

        self.emit_warnings(&loaded);

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
    fn emit_warnings(&self, loaded: &[LoadedConfig]) {
        let color = self.use_color_stderr();
        for warning in mcpwn::output::inventory::warnings(loaded) {
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

/// Discovery + loading: the two steps every command shares.
///
/// No path means global discovery; a path means project discovery under it.
fn collect(paths: &[PathBuf]) -> Vec<LoadedConfig> {
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

    loading::load_all(&configs)
}

fn describe_target(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        "(global MCP config locations)".to_owned()
    } else {
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
