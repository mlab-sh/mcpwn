//! Pattern rules over normalised tool text.
//!
//! This is where `yara-x` will be plugged in: a rule set is compiled once, then
//! matched against each tool's normalised description and schema descriptions,
//! and every match becomes a [`Finding`]. No YARA dependency yet; only the
//! seam it will slot into.
//!
//! Not implemented yet.

use crate::finding::Finding;
use crate::finding::{Category, Severity};
use crate::manifest::{ServerManifest, ToolManifest};

/// A single pattern rule, before it is handed to the matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Becomes the finding id, e.g. `MCPWN-TP-001`.
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    /// Source text of the rule (YARA-X source, once wired).
    pub source: String,
}

/// A compiled, reusable rule set.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// The rules shipped with mcpwn. Empty until the rule pack is written.
    pub fn builtin() -> Self {
        Self::default()
    }

    /// Compile a user-supplied rule set.
    ///
    /// Not implemented yet.
    pub fn compile(_source: &str) -> crate::Result<Self> {
        todo!("rules: compile a yara-x rule set")
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    /// Match every rule against one tool.
    ///
    /// Returns an empty list until the matcher lands.
    pub fn match_tool(&self, _server: &ServerManifest, _tool: &ToolManifest) -> Vec<Finding> {
        Vec::new()
    }
}
