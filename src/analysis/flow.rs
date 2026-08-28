//! Toxic flows: the danger that exists only in the combination.
//!
//! No tool here is dangerous alone. The risk appears when three roles coexist
//! in one agent's environment:
//!
//! ```text
//!   ingest   untrusted content enters the context and can steer the model
//!      ↓
//!   source   private state is read
//!      ↓
//!   sink     it leaves
//! ```
//!
//! Each server can be entirely legitimate; the environment assembled from them
//! is not. That is why this is a [`GlobalCheck`] — the flow routinely crosses
//! servers, and no per-tool view can see it.
//!
//! # Why one finding and not N³
//!
//! With five tools per role there are 125 triples, and all 125 say the same
//! thing: *this environment can exfiltrate*. The risk is a property of the
//! environment, not of any particular permutation, so the check emits **at most
//! one finding**, carrying a representative chain and listing every tool that
//! can fill each role. Reporting the cartesian product would bury the one
//! sentence that matters under its own restatements.

use serde::{Deserialize, Serialize};

use crate::analysis::capabilities::Capability;
use crate::analysis::check::{GlobalCheck, ScanContext};
use crate::analysis::roles::{self, Role, RoleConfidence, RoleTags};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::manifest::ToolRef;

/// One hop of a toxic flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStep {
    pub tool: ToolRef,
    /// The role this tool plays *at this position* in the chain.
    pub role: Role,
    /// Why this tool can fill the role.
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

    /// True when the chain both reads private state and can send it out.
    pub fn is_exfiltrating(&self) -> bool {
        self.steps.iter().any(|s| s.role == Role::Source)
            && self.steps.iter().any(|s| s.role == Role::Sink)
    }
}

/// Every tool of every scanned server, with its inferred roles.
#[derive(Debug, Clone, Default)]
pub struct FlowGraph {
    pub nodes: Vec<(ToolRef, RoleTags)>,
}

impl FlowGraph {
    pub fn from_nodes(nodes: Vec<(ToolRef, RoleTags)>) -> Self {
        Self { nodes }
    }

    /// Tag every tool in the scan.
    ///
    /// `capabilities` maps a tool to what the capability check already found
    /// for it, so that analysis is consumed rather than repeated.
    pub fn build(ctx: &ScanContext<'_>, capabilities: &[(ToolRef, Vec<Capability>)]) -> Self {
        let nodes = ctx
            .tools()
            .map(|tool| {
                let reference = tool.tool_ref();
                let found: &[Capability] = capabilities
                    .iter()
                    .find(|(r, _)| *r == reference)
                    .map(|(_, c)| c.as_slice())
                    .unwrap_or(&[]);
                (reference, roles::tag_tool(&tool, found))
            })
            .collect();
        Self { nodes }
    }

    /// Every tool that can fill `role`, clearest first.
    pub fn candidates(&self, role: Role) -> Vec<(&ToolRef, &roles::RoleTag)> {
        let mut out: Vec<(&ToolRef, &roles::RoleTag)> = self
            .nodes
            .iter()
            .filter_map(|(reference, tags)| tags.get(role).map(|tag| (reference, tag)))
            .collect();
        // Clear before ambiguous, then by name so the chosen chain is stable.
        out.sort_by(|a, b| a.1.confidence.cmp(&b.1.confidence).then(a.0.cmp(b.0)));
        out
    }

    /// The representative chain, if the environment has all three roles.
    ///
    /// One tool per role, preferring a clear tag over an ambiguous one, so the
    /// reported chain is the most solid one available rather than an arbitrary
    /// pick.
    pub fn chain(&self) -> Option<FlowChain> {
        let mut steps = Vec::with_capacity(3);
        for role in Role::CHAIN {
            let (reference, tag) = self.candidates(role).into_iter().next()?;
            steps.push(FlowStep::new(reference.clone(), role).with_note(tag.rationale.clone()));
        }
        Some(FlowChain::new(steps))
    }

    /// Whether the chain rests on any ambiguous tag.
    fn chain_is_clear(&self) -> bool {
        Role::CHAIN.iter().all(|&role| {
            self.candidates(role)
                .first()
                .is_some_and(|(_, tag)| tag.confidence == RoleConfidence::Clear)
        })
    }
}

/// The toxic-flow analyser.
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
        "Finds ingest -> source -> sink chains reachable across every loaded server."
    }

    fn check(&self, ctx: &ScanContext<'_>, prior: &[Finding]) -> Vec<Finding> {
        let graph = FlowGraph::build(ctx, &capabilities_by_tool(prior));

        let Some(chain) = graph.chain() else {
            // Missing any one of the three roles means no flow. In particular,
            // source + sink with no ingest is not reported: without untrusted
            // content entering, nothing steers the model into the chain.
            return Vec::new();
        };

        vec![finding(&graph, chain)]
    }
}

/// Read back what the capability check concluded, per tool.
fn capabilities_by_tool(prior: &[Finding]) -> Vec<(ToolRef, Vec<Capability>)> {
    let mut out: Vec<(ToolRef, Vec<Capability>)> = Vec::new();

    for finding in prior {
        let Some(capability) = Capability::from_finding_id(finding.id.as_str()) else {
            continue;
        };
        let Some(subject) = finding.primary_subject() else {
            continue;
        };
        match out.iter_mut().find(|(r, _)| r == subject) {
            Some((_, caps)) => {
                if !caps.contains(&capability) {
                    caps.push(capability);
                }
            }
            None => out.push((subject.clone(), vec![capability])),
        }
    }
    out
}

fn finding(graph: &FlowGraph, chain: FlowChain) -> Finding {
    let clear = graph.chain_is_clear();
    let severity = if clear {
        Severity::Critical
    } else {
        Severity::High
    };

    let servers: std::collections::BTreeSet<&str> =
        chain.steps.iter().map(|s| s.tool.server.as_str()).collect();
    let across = if servers.len() > 1 {
        format!(
            " The chain crosses {} servers ({}), so no single server looks wrong on its own.",
            servers.len(),
            servers.into_iter().collect::<Vec<_>>().join(", ")
        )
    } else {
        String::new()
    };

    let mut message = format!(
        "This environment holds all three links of an exfiltration chain: `{}` can bring in \
         content controlled by a third party, `{}` can read private state, and `{}` can send data \
         out. An instruction hidden in what the first tool retrieves can steer the agent into \
         calling the other two.{across} This is a structural risk, not an attack in progress: \
         nothing here says any of these tools is malicious or that anything has happened.",
        chain.steps[0].tool, chain.steps[1].tool, chain.steps[2].tool
    );

    if !clear {
        message.push_str(
            " At least one link rests on an ambiguous tag — a network tool whose direction could \
             not be determined is assumed to do both, on the principle that a missed flow is worse \
             than one to check — so this is reported as High rather than Critical.",
        );
    }

    let mut builder = Finding::builder(
        "MCPWN-FLOW-001",
        Category::ToxicFlow,
        severity,
        "Exfiltration chain: untrusted input, private data, and a way out",
    )
    .message(message)
    .confidence(if clear {
        Confidence::High
    } else {
        Confidence::Medium
    })
    .subjects(chain.steps.iter().map(|s| s.tool.clone()))
    .flow(chain)
    .remediation(
        "Break one link: drop a server the agent does not need, or require confirmation before \
         the sink can be called after untrusted content has entered the context.",
    );

    // Every alternative that can fill each role, so the reader can see the real
    // width of the exposure without a finding per permutation.
    for role in Role::CHAIN {
        let candidates = graph.candidates(role);
        let listed: Vec<String> = candidates
            .iter()
            .take(10)
            .map(|(reference, tag)| match tag.confidence {
                RoleConfidence::Clear => reference.to_string(),
                RoleConfidence::Ambiguous => format!("{reference} (ambiguous)"),
            })
            .collect();
        let mut excerpt = listed.join(", ");
        if candidates.len() > listed.len() {
            excerpt.push_str(&format!(", and {} more", candidates.len() - listed.len()));
        }
        builder = builder.evidence(Evidence::new(format!("{role} candidates"), excerpt));
    }

    builder = builder.evidence(Evidence::new(
        "coverage",
        "Role tagging is heuristic: it catches the clear cases and will miss tools whose \
         name and description do not say what they do.",
    ));

    builder.build()
}
