//! Argument parsing and command dispatch. Binary-only: the library knows
//! nothing about it.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use mcpwn::output::{render::TerminalRenderer, sarif};
use mcpwn::{Analyzer, AnalyzerConfig, Report, ServerManifest};

/// Static, offline security scanner for MCP servers.
#[derive(Debug, Parser)]
#[command(name = "mcpwn", version, about, long_about = None)]
pub struct Cli {
    /// Print per-finding detail (message, evidence, remediation).
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
    /// Scan MCP server configs for dangerous tool definitions.
    Scan(ScanArgs),
    /// Explain a finding id, e.g. `mcpwn explain MCPWN-TP-001`.
    Explain {
        /// The rule id to explain.
        id: String,
    },
}

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Config files or directories to scan. Defaults to the well-known MCP
    /// client config locations.
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

/// Process exit codes.
pub mod exit {
    /// Scan completed, nothing found.
    pub const CLEAN: i32 = 0;
    /// Scan completed, findings reported.
    pub const FINDINGS: i32 = 1;
    /// Something went wrong.
    pub const ERROR: i32 = 2;
}

impl Cli {
    /// Run the selected command; returns the process exit code.
    pub fn run(&self) -> Result<i32> {
        match &self.command {
            Command::Scan(args) => self.scan(args),
            Command::Explain { id } => Self::explain(id),
        }
    }

    fn scan(&self, args: &ScanArgs) -> Result<i32> {
        let target = describe_target(&args.paths);
        let servers = discover(&args.paths).context("discovering MCP server configs")?;

        let analyzer = Analyzer::with_config(AnalyzerConfig {
            target: Some(target),
            skip_flow: false,
        });
        let report = analyzer.analyze(&servers);

        let mut stdout = io::stdout().lock();
        self.emit(&report, args.format, &mut stdout)?;
        stdout.flush()?;

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
                    "\nnote: config discovery and the detection modules are not implemented yet."
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

    fn use_color(&self) -> bool {
        !self.no_color && io::stdout().is_terminal()
    }
}

/// Locate MCP client configs and parse the servers they declare.
///
/// Not implemented yet: returns no servers, so a scan produces an empty report.
fn discover(_paths: &[PathBuf]) -> Result<Vec<ServerManifest>> {
    Ok(Vec::new())
}

fn describe_target(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        "(default MCP config locations)".to_owned()
    } else {
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
