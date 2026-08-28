//! Terminal rendering of a discovery inventory: which configs were found, who
//! owns them, and how many servers each declares.

use std::io::{self, Write};

use owo_colors::{OwoColorize, Style};

use crate::enumerate::{EnumeratedServer, Enumeration};
use crate::loading::{LoadStatus, LoadedConfig};

/// Renders the result of `mcpwn discover`.
#[derive(Debug, Clone)]
pub struct InventoryRenderer {
    color: bool,
    verbose: bool,
}

impl Default for InventoryRenderer {
    fn default() -> Self {
        Self {
            color: true,
            verbose: false,
        }
    }
}

impl InventoryRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn render<W: Write>(&self, loaded: &[LoadedConfig], out: &mut W) -> io::Result<()> {
        if loaded.is_empty() {
            return writeln!(
                out,
                "no MCP configuration files found (this is not an error — nothing to scan)"
            );
        }

        let client_width = loaded
            .iter()
            .map(|l| l.config.client.label().len())
            .max()
            .unwrap_or(0);
        let scope_width = loaded
            .iter()
            .map(|l| l.config.scope.label().len())
            .max()
            .unwrap_or(0);

        for entry in loaded {
            self.row(entry, client_width, scope_width, out)?;
            if self.verbose {
                for server in &entry.servers {
                    let transport = server
                        .transport
                        .as_ref()
                        .map(|t| t.summary())
                        .unwrap_or_else(|| "(no launch method)".to_owned());
                    writeln!(out, "    {} — {}", server.name, transport)?;
                }
            }
        }

        self.summary(loaded, out)
    }

    /// The per-server enumeration table shown under the config table.
    pub fn render_servers<W: Write>(
        &self,
        servers: &[EnumeratedServer],
        out: &mut W,
    ) -> io::Result<()> {
        if servers.is_empty() {
            return Ok(());
        }

        let name_width = servers
            .iter()
            .map(|s| s.server.name.len())
            .max()
            .unwrap_or(0);

        writeln!(out, "\nservers")?;
        for entry in servers {
            let status = match &entry.outcome {
                Enumeration::Enumerated { protocol } => self.paint(
                    format!("{} tool(s) via {protocol}", entry.tool_count()),
                    Style::new().green(),
                ),
                Enumeration::NotPossible { reason } => {
                    self.paint(reason.clone(), Style::new().dimmed())
                }
                Enumeration::Failed { reason } => self.paint(reason.clone(), Style::new().red()),
            };
            writeln!(
                out,
                "  {:<name_width$}  {}",
                entry.server.name,
                status,
                name_width = name_width
            )?;

            if self.verbose {
                for tool in &entry.server.tools {
                    let summary: String = tool
                        .description
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .take(72)
                        .collect();
                    writeln!(out, "      {} — {}", tool.name, summary)?;
                }
            }
        }
        Ok(())
    }

    fn row<W: Write>(
        &self,
        entry: &LoadedConfig,
        client_width: usize,
        scope_width: usize,
        out: &mut W,
    ) -> io::Result<()> {
        let client = format!("{:<client_width$}", entry.config.client.label());
        let scope = format!("{:<scope_width$}", entry.config.scope.label());
        let count = match &entry.status {
            LoadStatus::Parsed => format!("{} server(s)", entry.servers.len()),
            _ => "—".to_owned(),
        };
        let marker = match &entry.status {
            LoadStatus::Parsed => String::new(),
            LoadStatus::Unsupported { reason } => {
                format!(
                    "  {}",
                    self.paint(format!("[{reason}]"), Style::new().yellow())
                )
            }
            LoadStatus::Skipped { reason } => format!(
                "  {}",
                self.paint(format!("[skipped: {reason}]"), Style::new().red())
            ),
        };

        writeln!(
            out,
            "{}  {}  {:>11}  {} ({}){}",
            self.paint(client, Style::new().bold()),
            self.paint(scope, Style::new().dimmed()),
            count,
            entry.config.path.display(),
            entry.config.format,
            marker
        )
    }

    fn summary<W: Write>(&self, loaded: &[LoadedConfig], out: &mut W) -> io::Result<()> {
        let servers: usize = loaded.iter().map(|l| l.servers.len()).sum();
        let parsed = loaded.iter().filter(|l| l.status.is_parsed()).count();
        let unparsed = loaded.len() - parsed;

        write!(
            out,
            "\n{} config(s), {} server(s) declared",
            loaded.len(),
            servers
        )?;
        if unparsed > 0 {
            write!(
                out,
                ", {}",
                self.paint(
                    format!("{unparsed} not parsed"),
                    Style::new().yellow().bold()
                )
            )?;
        }
        writeln!(out)
    }

    fn paint(&self, text: impl std::fmt::Display, style: Style) -> String {
        if self.color {
            format!("{}", text.style(style))
        } else {
            text.to_string()
        }
    }
}

/// The `warning:` lines that belong on stderr, one per problem.
pub fn warnings(loaded: &[LoadedConfig]) -> Vec<String> {
    loaded
        .iter()
        .filter_map(|entry| {
            let path = entry.config.path.display();
            match &entry.status {
                LoadStatus::Parsed => None,
                LoadStatus::Unsupported { reason } => Some(format!("{path}: {reason}")),
                LoadStatus::Skipped { reason } => Some(format!("{path}: {reason}")),
            }
        })
        .collect()
}

/// Enumeration warnings. A stdio server is *not* one of these: not enumerating
/// it is the intended behaviour, not a problem.
pub fn enumeration_warnings(servers: &[EnumeratedServer]) -> Vec<String> {
    servers
        .iter()
        .filter_map(|entry| match &entry.outcome {
            Enumeration::Failed { reason } => Some(format!("{}: {reason}", entry.server.name)),
            Enumeration::Enumerated { .. } | Enumeration::NotPossible { .. } => None,
        })
        .collect()
}
