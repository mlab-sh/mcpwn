//! Shadowing: one tool standing in for another, or rewriting its rules.
//!
//! A [`GlobalCheck`], because shadowing only exists between tools and the
//! interesting case is always across servers: the model is shown every tool of
//! every connected server in one flat list, with no indication of which server
//! each came from and no rule about what happens when two of them collide.
//!
//! Two mechanisms, three rules:
//!
//! * **Name collision.** Two servers expose the same tool name, or names that
//!   look identical without being identical. Which one the agent calls is not
//!   defined by the protocol, so a server that arrives second can take over a
//!   name a trusted server already had.
//! * **Cross-server instruction.** One server's tool description talks about
//!   another server's tool. Descriptions are read by the model as guidance, so
//!   a server can change how a tool it does not own gets called without that
//!   tool, or its server, being involved at all.

use std::collections::BTreeMap;

use crate::analysis::check::{GlobalCheck, ScanContext};
use crate::analysis::{normalize, schema};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::lock::ServerId;
use crate::manifest::ToolRef;

/// One tool, reduced to what shadowing detection needs.
#[derive(Debug, Clone)]
struct Node {
    reference: ToolRef,
    /// Transport identity, so the same endpoint declared under two config names
    /// counts as one server rather than as its own shadow.
    server: ServerId,
    /// Comparison key for the name: see [`fingerprint`].
    fingerprint: String,
    /// Surface forms another description might spell this name as.
    forms: Vec<String>,
    /// Every model-visible text of the tool, labelled, normalised, lowercased.
    texts: Vec<(String, String)>,
}

/// Fold a tool name into a comparison key.
///
/// Invisible characters are stripped, separators dropped, case folded, and
/// look-alike letters resolved through the UTS #39 confusables table. So
/// `read_file`, `read-file`, `readFile`, `readfile` and a Cyrillic twin of any
/// of them all land on one key.
///
/// Dropping separators matters: swapping an underscore for a hyphen is the
/// cheapest impersonation there is, and it survives every check that compares
/// names literally.
fn fingerprint(name: &str) -> String {
    let cleaned = normalize::normalize(name).cleaned;
    let letters: String = cleaned
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    normalize::skeleton(&letters)
}

/// The spellings a description might use for a tool name.
///
/// Separator variants and the run-together form, so `send_email` is still found
/// when written `send-email`, `sendemail`, or namespaced as
/// `mcp__mail__send_email`.
///
/// The space-separated form (`send email`) is deliberately **not** included: it
/// turns every description containing the plain English words into a match.
/// Recognising a paraphrased reference is a different problem, and it is not
/// this rule's.
fn surface_forms(name: &str) -> Vec<String> {
    let lowered = name.to_lowercase();
    let mut forms = vec![lowered.clone()];

    let underscored: String = lowered
        .chars()
        .map(|c| if c == '-' || c == '.' { '_' } else { c })
        .collect();
    let hyphenated: String = lowered
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect();
    let joined: String = lowered.chars().filter(|c| c.is_alphanumeric()).collect();

    for form in [underscored, hyphenated, joined] {
        if form.len() >= 4 && !forms.contains(&form) {
            forms.push(form);
        }
    }
    forms
}

/// A name is distinctive enough to be looked for inside prose when it carries a
/// separator or is long.
///
/// Without this, a tool named `search` or `add` matches every description that
/// happens to use the word, and the rule reports nothing but noise.
fn is_distinctive(name: &str) -> bool {
    name.chars().count() >= 10 || name.contains('_') || name.contains('-') || name.contains("::")
}

fn nodes(ctx: &ScanContext<'_>) -> Vec<Node> {
    ctx.servers()
        .iter()
        .flat_map(|server| {
            let id = ServerId::from_manifest(server);
            server.tools.iter().map(move |tool| {
                // Parameter descriptions are read by the model exactly like the
                // tool description is, so they are just as good a place to put
                // an instruction about someone else's tool.
                let mut texts = vec![(
                    "description".to_owned(),
                    normalize::normalize(&tool.description)
                        .cleaned
                        .to_lowercase(),
                )];
                if let Some(input_schema) = tool.input_schema.as_ref() {
                    for param in schema::flatten(input_schema).iter() {
                        if let Some(description) = &param.description {
                            texts.push((
                                format!("inputSchema.{}.description", param.path),
                                normalize::normalize(description).cleaned.to_lowercase(),
                            ));
                        }
                    }
                }
                texts.retain(|(_, text)| !text.is_empty());

                Node {
                    reference: ToolRef::new(&server.name, &tool.name),
                    server: id.clone(),
                    fingerprint: fingerprint(&tool.name),
                    forms: surface_forms(&tool.name),
                    texts,
                }
            })
        })
        .collect()
}

/// The shadowing analyser.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowingCheck;

impl ShadowingCheck {
    pub fn new() -> Self {
        Self
    }
}

impl GlobalCheck for ShadowingCheck {
    fn id(&self) -> &'static str {
        "shadowing"
    }

    fn description(&self) -> &'static str {
        "Finds tools that impersonate another tool's name, or that rewrite how a \
         tool on another server should be called."
    }

    fn check(&self, ctx: &ScanContext<'_>, _prior: &[Finding]) -> Vec<Finding> {
        let nodes = nodes(ctx);
        let mut findings = collisions(&nodes);
        findings.extend(cross_references(&nodes));
        findings
    }
}

// ---------------------------------------------------------------------------
// Name collisions
// ---------------------------------------------------------------------------

/// Group tools by folded name and report the groups that span servers.
///
/// One finding per colliding name, never one per pair: three servers exposing
/// `read_file` is one problem with three participants, not three problems.
fn collisions(nodes: &[Node]) -> Vec<Finding> {
    let mut groups: BTreeMap<&str, Vec<&Node>> = BTreeMap::new();
    for node in nodes {
        groups.entry(&node.fingerprint).or_default().push(node);
    }

    let mut findings = Vec::new();
    for group in groups.values() {
        let servers: std::collections::BTreeSet<&ServerId> =
            group.iter().map(|n| &n.server).collect();
        if servers.len() < 2 {
            continue; // one server listing a name twice is not shadowing.
        }

        let names: std::collections::BTreeSet<&str> =
            group.iter().map(|n| n.reference.tool.as_str()).collect();
        let subjects: Vec<ToolRef> = group.iter().map(|n| n.reference.clone()).collect();
        let listed = subjects
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        // Identical spelling is a collision. Different spellings that fold to
        // the same key are an impersonation: nothing produces a homoglyph twin
        // of a name on another server by accident.
        let identical = names.len() == 1;
        let finding =
            if identical {
                Finding::builder(
                "MCPWN-SHA-001",
                Category::Shadowing,
                Severity::High,
                format!("Tool name exposed by several servers: `{}`", group[0].reference.tool),
            )
            .message(format!(
                "{} servers expose a tool called `{}`. The model is shown every tool of every \
                 connected server in one flat list, and the protocol does not say which one wins \
                 when two share a name. A server that connects alongside a trusted one can take \
                 over the name the agent was told to use.",
                servers.len(),
                group[0].reference.tool
            ))
            .confidence(Confidence::High)
            .remediation(
                "Decide which server should own this name. Disconnect the other, or rename its \
                 tool, before relying on either.",
            )
            } else {
                Finding::builder(
                "MCPWN-SHA-002",
                Category::Shadowing,
                Severity::Critical,
                format!(
                    "Tool names that look alike across servers: {}",
                    names
                        .iter()
                        .map(|n| format!("`{n}`"))
                        .collect::<Vec<_>>()
                        .join(" vs ")
                ),
            )
            .message(format!(
                "These tool names are spelled differently but render the same, and they sit on \
                 different servers: {listed}. Folding away invisible characters, case and \
                 look-alike letters collapses them onto one name. A reviewer comparing the two \
                 lists sees no difference; the agent has two tools it cannot tell apart."
            ))
            .confidence(Confidence::High)
            .remediation(
                "Compare the raw bytes of both names. A name that only looks like another one is \
                 there to be mistaken for it.",
            )
            };

        findings.push(
            finding
                .subjects(subjects)
                .evidence(Evidence::new("tools", listed))
                .evidence(Evidence::new(
                    "servers",
                    servers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ))
                .build(),
        );
    }
    findings
}

// ---------------------------------------------------------------------------
// Cross-server references
// ---------------------------------------------------------------------------

/// Tools whose description names a tool belonging to a different server.
///
/// Grouped by the tool doing the referencing, so a description mentioning four
/// foreign tools is one finding with four participants.
///
/// References within one server are **not** reported: `query-docs` telling the
/// model to call `resolve-library-id` first is ordinary, correct documentation,
/// and it is what real servers do. The finding is about a server reaching
/// across a boundary it does not own.
fn cross_references(nodes: &[Node]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for node in nodes {
        if node.texts.is_empty() {
            continue;
        }

        // Which field carried the reference is part of the answer: a foreign
        // tool named in a parameter description is hidden further from view
        // than one named in the tool description.
        let mut referenced: Vec<(&Node, &str)> = Vec::new();
        for other in nodes {
            if other.server == node.server || !is_distinctive(&other.reference.tool) {
                continue;
            }
            if let Some((label, _)) = node
                .texts
                .iter()
                .find(|(_, text)| other.forms.iter().any(|form| mentions(text, form)))
            {
                referenced.push((other, label.as_str()));
            }
        }

        if referenced.is_empty() {
            continue;
        }

        let names: std::collections::BTreeSet<String> = referenced
            .iter()
            .map(|(n, _)| n.reference.to_string())
            .collect();
        let listed = names.iter().cloned().collect::<Vec<_>>().join(", ");
        let fields: std::collections::BTreeSet<&str> =
            referenced.iter().map(|(_, label)| *label).collect();

        let mut subjects = vec![node.reference.clone()];
        subjects.extend(referenced.iter().map(|(n, _)| n.reference.clone()));

        findings.push(
            Finding::builder(
                "MCPWN-SHA-003",
                Category::Shadowing,
                Severity::High,
                format!(
                    "`{}` gives instructions about another server's tool",
                    node.reference.tool
                ),
            )
            .message(format!(
                "The {} of `{}` names {}, which belong{} to a different server. Tool text is read \
                 by the model as guidance, so this server is in a position to change how a tool it \
                 does not own gets called, without that tool or its server being involved. Whether \
                 the wording here is hostile is a separate question; the reach is the finding.",
                fields.iter().copied().collect::<Vec<_>>().join(" and "),
                node.reference,
                listed,
                if names.len() > 1 { "" } else { "s" }
            ))
            .confidence(Confidence::Medium)
            .subjects(subjects)
            .remediation(
                "Read this text in full and decide whether this server should be able to say \
                 anything about the other one's tools. If not, disconnect it.",
            )
            .evidence(Evidence::new("referenced tools", listed))
            .evidence(Evidence::new(
                "found in",
                fields.iter().copied().collect::<Vec<_>>().join(", "),
            ))
            .evidence(Evidence::new(
                "text",
                node.texts
                    .iter()
                    .filter(|(label, _)| fields.contains(label.as_str()))
                    .map(|(_, text)| text.chars().take(240).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(" | "),
            ))
            .build(),
        );
    }

    findings
}

/// Whether `haystack` names `needle` as its own identifier.
///
/// The characters on either side must not be alphanumeric, so `read_file` is
/// not found inside `thread_read_filename`. Separators *are* allowed as
/// boundaries, so a namespaced reference such as `mcp__mail__send_email` still
/// resolves to `send_email`: that is how several clients spell a tool once it
/// is qualified by its server.
fn mentions(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut from = 0;

    while let Some(offset) = haystack[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}
