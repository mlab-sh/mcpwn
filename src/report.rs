//! The container handed back by the [`crate::analyzer::Analyzer`] and consumed
//! by every renderer.

use serde::{Deserialize, Serialize};

use crate::finding::{Category, Finding, Severity};

/// What was scanned, and how much of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanMeta {
    /// What the user pointed mcpwn at (a path, a config name, `-` for stdin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Number of MCP servers seen.
    pub servers: usize,
    /// Number of tools seen across those servers.
    pub tools: usize,
    /// Version of mcpwn that produced the report.
    pub scanner_version: String,
}

impl ScanMeta {
    pub fn new(target: Option<String>) -> Self {
        Self {
            target,
            servers: 0,
            tools: 0,
            scanner_version: crate::VERSION.to_owned(),
        }
    }
}

/// A full scan result: metadata plus every finding produced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub meta: ScanMeta,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(meta: ScanMeta) -> Self {
        Self {
            meta,
            findings: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn extend(&mut self, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(findings);
    }

    /// Findings of a given severity, in insertion order.
    pub fn by_severity(&self, severity: Severity) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.severity == severity)
    }

    /// Findings of a given category, in insertion order.
    pub fn by_category(&self, category: Category) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.category == category)
    }

    pub fn count_severity(&self, severity: Severity) -> usize {
        self.by_severity(severity).count()
    }

    /// The worst severity present, if any. Drives the CLI exit code.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Sort findings most-severe first; ties broken by rule id for stable output.
    pub fn sort(&mut self) {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.subjects.cmp(&b.subjects))
        });
    }

    pub fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
