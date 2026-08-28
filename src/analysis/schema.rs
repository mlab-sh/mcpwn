//! Analysis of a tool's JSON Schema (`inputSchema`).
//!
//! Two things matter here: what the schema *declares* (parameter names, types,
//! whether it accepts free-form objects) and what its `description` fields say,
//! since those are read by the model exactly like the tool description is.
//!
//! Not implemented yet.

use serde_json::Value;

use crate::finding::Finding;
use crate::manifest::{ServerManifest, ToolManifest};

/// A flattened view of one parameter of an input schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Dotted path, e.g. `options.path`.
    pub path: String,
    /// JSON Schema `type`, when declared.
    pub ty: Option<String>,
    pub required: bool,
    /// Per-parameter description — model-visible, therefore attacker-usable.
    pub description: Option<String>,
}

/// Walk an input schema and flatten it into [`Param`]s.
///
/// Not implemented yet.
pub fn flatten(_schema: &Value) -> Vec<Param> {
    Vec::new()
}

/// Inspect one tool's input schema.
///
/// Returns an empty list until the detection logic lands.
pub fn analyze_tool(_server: &ServerManifest, _tool: &ToolManifest) -> Vec<Finding> {
    Vec::new()
}
