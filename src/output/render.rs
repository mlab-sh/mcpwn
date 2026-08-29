//! Terminal rendering: findings grouped by severity, ANSI colours optional.
//!
//! Writes to any [`Write`], so it is testable and the engine stays I/O-free.
//! The layout is deliberately minimal for now: it will grow per-category
//! detail blocks as the detection modules land.

use std::io::{self, Write};

use owo_colors::{OwoColorize, Style};

use crate::finding::{Finding, Severity};
use crate::report::Report;

/// Renders a report as coloured, severity-grouped terminal output.
#[derive(Debug, Clone)]
pub struct TerminalRenderer {
    color: bool,
    verbose: bool,
}

impl Default for TerminalRenderer {
    fn default() -> Self {
        Self {
            color: true,
            verbose: false,
        }
    }
}

impl TerminalRenderer {
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

    /// Write the whole report.
    pub fn render<W: Write>(&self, report: &Report, out: &mut W) -> io::Result<()> {
        self.header(report, out)?;

        for severity in Severity::ALL {
            let group: Vec<&Finding> = report.by_severity(severity).collect();
            if group.is_empty() {
                continue;
            }
            writeln!(
                out,
                "\n{} ({})",
                self.paint(severity.slug().to_uppercase(), severity_style(severity)),
                group.len()
            )?;
            for finding in group {
                self.finding(finding, out)?;
            }
        }

        self.summary(report, out)
    }

    fn header<W: Write>(&self, report: &Report, out: &mut W) -> io::Result<()> {
        let target = report.meta.target.as_deref().unwrap_or("(no target)");
        writeln!(
            out,
            "{} {}  {}",
            self.paint(crate::NAME, Style::new().bold().cyan()),
            crate::VERSION,
            self.paint(target, Style::new().dimmed())
        )?;
        writeln!(
            out,
            "{} server(s), {} tool(s) analysed",
            report.meta.servers, report.meta.tools
        )
    }

    fn finding<W: Write>(&self, finding: &Finding, out: &mut W) -> io::Result<()> {
        // A config finding has no tool: it is attached to the server instead.
        let subjects = if finding.subjects.is_empty() {
            match &finding.server {
                Some(server) => format!("  [{server}]"),
                None => String::new(),
            }
        } else {
            let names: Vec<String> = finding.subjects.iter().map(ToString::to_string).collect();
            format!("  [{}]", names.join(", "))
        };
        writeln!(
            out,
            "  {} {}{}",
            self.paint(finding.id.as_str(), Style::new().dimmed()),
            finding.title,
            subjects
        )?;

        // A toxic flow is a sequence, so it is drawn as one: top to bottom,
        // one link per line. An ASCII graph would be less readable, not more.
        if let Some(flow) = &finding.flow {
            let width = flow
                .steps
                .iter()
                .map(|s| s.role.slug().len())
                .max()
                .unwrap_or(0);
            for (i, step) in flow.steps.iter().enumerate() {
                if i > 0 {
                    writeln!(out, "      {:>width$}  |", "")?;
                    writeln!(out, "      {:>width$}  v", "")?;
                }
                writeln!(
                    out,
                    "      {}  {}",
                    self.paint(format!("{:>width$}", step.role.slug()), Style::new().bold()),
                    step.tool
                )?;
                if self.verbose {
                    if let Some(note) = &step.note {
                        writeln!(out, "      {:>width$}     {note}", "")?;
                    }
                }
            }
        }

        if self.verbose {
            if !finding.message.is_empty() {
                writeln!(out, "      {}", finding.message)?;
            }
            for evidence in &finding.evidence {
                writeln!(out, "      {}: {}", evidence.label, evidence.excerpt)?;
            }
            if let Some(fix) = &finding.remediation {
                writeln!(out, "      fix: {fix}")?;
            }
        }

        Ok(())
    }

    fn summary<W: Write>(&self, report: &Report, out: &mut W) -> io::Result<()> {
        if report.is_empty() {
            return writeln!(
                out,
                "\n{}",
                self.paint("no findings", Style::new().green().bold())
            );
        }
        let counts: Vec<String> = Severity::ALL
            .iter()
            .map(|s| (s, report.count_severity(*s)))
            .filter(|(_, n)| *n > 0)
            .map(|(s, n)| format!("{n} {s}"))
            .collect();
        writeln!(
            out,
            "\n{} finding(s): {}",
            report.findings.len(),
            counts.join(", ")
        )
    }

    /// Apply a style only when colour is enabled.
    fn paint(&self, text: impl std::fmt::Display, style: Style) -> String {
        if self.color {
            format!("{}", text.style(style))
        } else {
            text.to_string()
        }
    }
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::new().bright_red().bold(),
        Severity::High => Style::new().red().bold(),
        Severity::Medium => Style::new().yellow().bold(),
        Severity::Low => Style::new().blue(),
        Severity::Info => Style::new().dimmed(),
    }
}
