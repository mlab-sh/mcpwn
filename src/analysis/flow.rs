//! Toxic-flow graph: the `source -> ingest -> sink` chains reachable across
//! every server the agent has loaded at once.
//!
//! Roles come from [`crate::analysis::roles`]; this module only builds the
//! graph and walks it. Cross-server chains are the interesting case — each
//! server looks harmless alone.
//!
//! Not implemented yet.

use serde::{Deserialize, Serialize};

use crate::analysis::check::{GlobalCheck, ScanContext};
use crate::analysis::roles::{Role, RoleTags};
use crate::finding::Finding;
use crate::manifest::{ServerManifest, ToolRef};

/// One hop of a toxic flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStep {
    pub tool: ToolRef,
    /// The role this tool plays *at this position* in the chain.
    pub role: Role,
    /// Why this hop connects to the next one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl FlowStep {
    pub fn new(tool: ToolRef, role: Role) -> Self {
        Self {
            tool,
            role,
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// An ordered chain of hops, attached to a [`Finding`] of category
/// [`crate::finding::Category::ToxicFlow`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FlowChain {
    pub steps: Vec<FlowStep>,
}

impl FlowChain {
    pub fn new(steps: Vec<FlowStep>) -> Self {
        Self { steps }
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// `server::tool -> server::tool -> ...`, for one-line rendering.
    pub fn render_inline(&self) -> String {
        self.steps
            .iter()
            .map(|s| s.tool.to_string())
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// True when the chain both reads sensitive state and can send it out.
    pub fn is_exfiltrating(&self) -> bool {
        self.steps.iter().any(|s| s.role == Role::Source)
            && self.steps.iter().any(|s| s.role == Role::Sink)
    }
}

/// Every tool of every scanned server, with its inferred roles — the node set
/// the flow walker operates on.
#[derive(Debug, Clone, Default)]
pub struct FlowGraph {
    pub nodes: Vec<(ToolRef, RoleTags)>,
}

impl FlowGraph {
    /// Build the graph from already role-tagged tools.
    pub fn from_nodes(nodes: Vec<(ToolRef, RoleTags)>) -> Self {
        Self { nodes }
    }

    pub fn tools_with(&self, role: Role) -> impl Iterator<Item = &ToolRef> {
        self.nodes
            .iter()
            .filter(move |(_, tags)| tags.has(role))
            .map(|(tool, _)| tool)
    }

    /// Enumerate the toxic chains present in the graph.
    ///
    /// Not implemented yet.
    pub fn chains(&self) -> Vec<FlowChain> {
        Vec::new()
    }
}

/// The toxic-flow analyser.
///
/// A [`GlobalCheck`] rather than a per-tool one: a flow only exists *between*
/// tools, often across servers that each look harmless alone, so it cannot be
/// expressed one tool at a time. Registered today so the global level of the
/// pipeline is wired and exercised; the walker itself is still empty.
#[derive(Debug, Default, Clone, Copy)]
pub struct ToxicFlowCheck;

impl ToxicFlowCheck {
    pub fn new() -> Self {
        Self
    }
}

impl GlobalCheck for ToxicFlowCheck {
    fn id(&self) -> &'static str {
        "toxic-flow"
    }

    fn description(&self) -> &'static str {
        "Finds source -> ingest -> sink chains reachable across every loaded server."
    }

    fn check(&self, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        Vec::new()
    }
}

/// Build the graph and report the chains found across all servers.
///
/// Returns an empty list until the walker lands.
pub fn analyze(_servers: &[ServerManifest]) -> Vec<Finding> {
    Vec::new()
}
