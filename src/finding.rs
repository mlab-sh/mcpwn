//! The central result type of the whole engine.
//!
//! Every analysis module (`schema`, `roles`, `flow`, `rules`, ...) produces
//! [`Finding`]s, and every consumer (`mcpwn-cli`, `mcpwn-sarif`) reads them.
//! Nothing else crosses the boundary, so this type is deliberately the most
//! carefully specified one in the crate.

use serde::{Deserialize, Serialize};

use crate::analysis::flow::FlowChain;
use crate::manifest::ToolRef;

/// A stable, human-quotable rule identifier, e.g. `MCPWN-TP-001`.
///
/// It is the key used by `mcpwn explain <ID>` and by SARIF's `ruleId`, so it
/// must stay stable across releases once published.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub String);

impl FindingId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for FindingId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// What class of problem a finding belongs to.
///
/// One variant per detection family; the roadmap in the README maps 1:1 onto
/// these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Category {
    /// Instructions smuggled into a tool description to steer the agent.
    ToolPoisoning,
    /// Hidden / unreadable content: zero-width chars, homoglyphs, encodings.
    Obfuscation,
    /// A tool that impersonates or overrides another server's tool.
    Shadowing,
    /// Behaviour that can change after the user approved the tool.
    RugPull,
    /// Excessive or dangerous capability requested by a tool.
    Capability,
    /// A source -> ingest -> sink chain that can exfiltrate data.
    ToxicFlow,
    /// A defect confirmed by interacting with a live server, rather than
    /// inferred from what it declares. Only `mcpwn audit` produces these.
    Vulnerability,
}

impl Category {
    /// Short, stable machine name (also used as the SARIF rule tag).
    pub fn slug(self) -> &'static str {
        match self {
            Category::ToolPoisoning => "tool-poisoning",
            Category::Obfuscation => "obfuscation",
            Category::Shadowing => "shadowing",
            Category::RugPull => "rug-pull",
            Category::Capability => "capability",
            Category::ToxicFlow => "toxic-flow",
            Category::Vulnerability => "vulnerability",
        }
    }

    pub const ALL: [Category; 7] = [
        Category::ToolPoisoning,
        Category::Obfuscation,
        Category::Shadowing,
        Category::RugPull,
        Category::Capability,
        Category::ToxicFlow,
        Category::Vulnerability,
    ];
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// How bad it is.
///
/// Declared in *ascending* order so the derived `Ord` is meaningful:
/// `Info < Low < Medium < High < Critical`. Renderers sort descending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn slug(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Descending order: the order findings are presented in.
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// How sure the engine is. Static analysis over free-form English descriptions
/// is inherently fuzzy, so this is reported rather than hidden.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

/// A concrete piece of the manifest that justifies the finding.
///
/// Kept intentionally coarse for now: a label plus the offending excerpt, and
/// optionally where it lives (a JSON pointer into the manifest, and a byte span
/// so SARIF can point at a region).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// e.g. `"description"`, `"inputSchema.properties.path"`.
    pub label: String,
    /// The excerpt itself, already truncated for display.
    pub excerpt: String,
    /// RFC 6901 JSON pointer into the source manifest, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// Byte offsets into the raw manifest text, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
}

impl Evidence {
    pub fn new(label: impl Into<String>, excerpt: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            excerpt: excerpt.into(),
            pointer: None,
            span: None,
        }
    }

    pub fn with_pointer(mut self, pointer: impl Into<String>) -> Self {
        self.pointer = Some(pointer.into());
        self
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }
}

/// Half-open byte range `[start, end)` in the raw manifest source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// A single security observation about one or more MCP tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Finding {
    /// Stable rule id (`MCPWN-XX-000`).
    pub id: FindingId,
    pub category: Category,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    /// One-line headline, imperative-free, e.g. "Hidden instructions in tool description".
    pub title: String,
    /// The full explanation shown to the user.
    pub message: String,
    /// Every tool this finding is about. Single-tool findings have exactly one;
    /// toxic-flow findings have several.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<ToolRef>,
    /// The server a finding is about when it concerns no particular tool; a
    /// secret in its config, an unpinned launch command. Tool findings leave it
    /// empty: their subject already names the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// For [`Category::ToxicFlow`]: the ordered source -> ingest -> sink chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<FlowChain>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// What the user should do about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    /// Start building a finding. All optional parts default to empty.
    pub fn builder(
        id: impl Into<FindingId>,
        category: Category,
        severity: Severity,
        title: impl Into<String>,
    ) -> FindingBuilder {
        FindingBuilder {
            finding: Finding {
                id: id.into(),
                category,
                severity,
                confidence: Confidence::default(),
                title: title.into(),
                message: String::new(),
                subjects: Vec::new(),
                server: None,
                flow: None,
                evidence: Vec::new(),
                remediation: None,
            },
        }
    }

    /// The tool this finding is primarily about, if any.
    pub fn primary_subject(&self) -> Option<&ToolRef> {
        self.subjects.first()
    }

    /// What the finding is attached to, for display: `server::tool`, or the
    /// bare server name for a server-scoped finding.
    pub fn scope(&self) -> Option<String> {
        match (self.subjects.first(), &self.server) {
            (Some(subject), _) => Some(subject.to_string()),
            (None, Some(server)) => Some(server.clone()),
            (None, None) => None,
        }
    }
}

/// Ergonomic construction so analysis modules stay readable.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.finding.message = message.into();
        self
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.finding.confidence = confidence;
        self
    }

    pub fn subject(mut self, tool: ToolRef) -> Self {
        self.finding.subjects.push(tool);
        self
    }

    /// Attach the finding to a server rather than to a tool.
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.finding.server = Some(server.into());
        self
    }

    pub fn subjects(mut self, tools: impl IntoIterator<Item = ToolRef>) -> Self {
        self.finding.subjects.extend(tools);
        self
    }

    pub fn flow(mut self, chain: FlowChain) -> Self {
        self.finding.flow = Some(chain);
        self
    }

    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.finding.evidence.push(evidence);
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.finding.remediation = Some(remediation.into());
        self
    }

    pub fn build(self) -> Finding {
        self.finding
    }
}
