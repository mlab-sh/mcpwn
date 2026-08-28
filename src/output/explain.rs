//! Terminal rendering for `mcpwn explain`.

use std::io::{self, Write};

use owo_colors::{OwoColorize, Style};

use crate::explain::RuleDoc;
use crate::finding::Severity;

/// Renders one rule, or the whole catalogue.
#[derive(Debug, Clone)]
pub struct ExplainRenderer {
    color: bool,
}

impl Default for ExplainRenderer {
    fn default() -> Self {
        Self { color: true }
    }
}

impl ExplainRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// The full page for one rule.
    pub fn render<W: Write>(&self, rule: &RuleDoc, out: &mut W) -> io::Result<()> {
        writeln!(
            out,
            "{}  {}",
            self.paint(rule.id, Style::new().bold()),
            rule.title
        )?;
        writeln!(
            out,
            "{}",
            self.paint(
                format!(
                    "{} · {} · check: {}",
                    rule.severity, rule.category, rule.check
                ),
                severity_style(rule.severity),
            )
        )?;

        self.section("WHAT IT MEANS", rule.detail, out)?;
        if let Some(example) = rule.example {
            self.section("EXAMPLE", example, out)?;
        }
        self.section("WHAT TO DO", rule.remediation, out)?;
        self.section(
            "WHEN IT FIRES ON SOMETHING HARMLESS",
            rule.expected_noise,
            out,
        )?;
        Ok(())
    }

    /// One line per rule, for `mcpwn explain` with no argument.
    pub fn render_index<W: Write>(&self, rules: &[RuleDoc], out: &mut W) -> io::Result<()> {
        writeln!(
            out,
            "{} rule(s). `mcpwn explain <ID>` for the detail.\n",
            rules.len()
        )?;

        let width = rules
            .iter()
            .map(|r| r.severity.slug().len())
            .max()
            .unwrap_or(0);
        // `MCPWN-FLOW-001` is a character longer than the others; pad so the
        // columns line up whatever ids exist.
        let id_width = rules.iter().map(|r| r.id.len()).max().unwrap_or(0);
        for rule in rules {
            writeln!(
                out,
                "  {}  {}  {}",
                self.paint(format!("{:<id_width$}", rule.id), Style::new().bold()),
                self.paint(
                    format!("{:<width$}", rule.severity.slug()),
                    severity_style(rule.severity)
                ),
                rule.summary
            )?;
        }
        Ok(())
    }

    fn section<W: Write>(&self, heading: &str, body: &str, out: &mut W) -> io::Result<()> {
        writeln!(out, "\n{}", self.paint(heading, Style::new().bold()))?;
        for line in body.lines() {
            if line.is_empty() {
                writeln!(out)?;
            } else {
                writeln!(out, "  {line}")?;
            }
        }
        Ok(())
    }

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
