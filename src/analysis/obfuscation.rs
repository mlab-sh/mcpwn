//! Obfuscation analysis: text a human reviewer and a model do not read the same.
//!
//! Every model-visible string of a tool goes through [`super::normalize`], and
//! whatever that reports becomes a finding here. The check itself holds no
//! Unicode knowledge: it maps note kinds to severities and writes the message.
//!
//! Unlike [`super::capabilities`], most of what this reports is **not**
//! ordinary. A tool description has no reason to contain a zero-width space,
//! and none at all to contain tag characters. The one category that needs care
//! is mixed script, where legitimate multilingual text exists; see
//! [`super::normalize::mixed_script_notes`]'s reasoning for how that is kept
//! narrow.

use crate::analysis::check::{ScanContext, ToolCheck, ToolContext};
use crate::analysis::normalize::{self, NormalizationNote, NoteKind};
use crate::analysis::schema;
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::manifest::ToolRef;

/// Rule id per obfuscation kind.
pub fn finding_id(kind: NoteKind) -> &'static str {
    match kind {
        NoteKind::TagCharacter => "MCPWN-OBF-001",
        NoteKind::InvisibleCharacter => "MCPWN-OBF-002",
        NoteKind::BidiControl => "MCPWN-OBF-003",
        NoteKind::MixedScript => "MCPWN-OBF-004",
        NoteKind::ControlCharacter => "MCPWN-OBF-005",
        NoteKind::EncodedPayload => "MCPWN-OBF-006",
    }
}

/// Severity per obfuscation kind.
///
/// Tag characters sit alone at the top: the block encodes printable ASCII as
/// invisible codepoints, it has no use in prose, and text hidden in it was put
/// there to be read by a model and not by a person. That is the whole attack,
/// with no benign reading.
///
/// Zero-width characters and bidi overrides are High: both defeat a human
/// reviewer, and both have rare-but-real legitimate uses in text (joiners in
/// Indic and Arabic scripts, bidi in genuinely bidirectional text), so they
/// stop short of Critical.
///
/// Mixed script is Medium: legitimate multilingual text exists, and this is
/// the one kind here with a real false-positive story.
pub fn severity(kind: NoteKind) -> Severity {
    match kind {
        NoteKind::TagCharacter => Severity::Critical,
        NoteKind::InvisibleCharacter => Severity::High,
        NoteKind::BidiControl => Severity::High,
        NoteKind::MixedScript => Severity::Medium,
        NoteKind::ControlCharacter => Severity::Medium,
        // Encoding is not invisibility: a reviewer sees *something*, just not
        // what it says. Below the zero-width family for that reason.
        NoteKind::EncodedPayload => Severity::Medium,
    }
}

fn title(kind: NoteKind) -> &'static str {
    match kind {
        NoteKind::TagCharacter => "Hidden text encoded as Unicode tag characters",
        NoteKind::InvisibleCharacter => "Invisible characters",
        NoteKind::BidiControl => "Bidirectional override",
        NoteKind::MixedScript => "Mixed-script word",
        NoteKind::ControlCharacter => "Unexpected control characters",
        NoteKind::EncodedPayload => "Encoded text hidden in a description",
    }
}

fn statement(kind: NoteKind) -> &'static str {
    match kind {
        NoteKind::TagCharacter => {
            "these codepoints mirror printable ASCII but render as nothing, so the text they \
             spell is read by the model and invisible to anyone reviewing the tool"
        }
        NoteKind::InvisibleCharacter => {
            "zero-width characters render as nothing, so the text a reviewer sees and the text \
             the model receives are not the same"
        }
        NoteKind::BidiControl => {
            "bidirectional controls reorder how text is displayed, so the rendered description \
             can differ from the one the model is given"
        }
        NoteKind::MixedScript => {
            "a single word mixes writing systems using characters that look like Latin letters, \
             which is how a name is made to impersonate another"
        }
        NoteKind::ControlCharacter => {
            "control characters have no meaning in a description and can truncate or corrupt it \
             when displayed"
        }
        NoteKind::EncodedPayload => {
            "this run of base64 or hex decodes to readable text, so the description carries a \
             message a reviewer would skip over as noise and a model may well decode"
        }
    }
}

fn remediation(kind: NoteKind) -> &'static str {
    match kind {
        NoteKind::TagCharacter => {
            "Read the decoded text below and treat this server as hostile until it is explained."
        }
        NoteKind::InvisibleCharacter | NoteKind::BidiControl | NoteKind::ControlCharacter => {
            "Inspect the raw bytes of this field; compare what renders with what is stored."
        }
        NoteKind::EncodedPayload => {
            "Read the decoded text below and decide whether it belongs in a tool description."
        }
        NoteKind::MixedScript => "Check whether this name is impersonating another tool or server.",
    }
}

/// Every model-visible string of a tool, with a label for the finding.
fn fields(tool: &ToolContext<'_>) -> Vec<(String, String)> {
    let mut out = vec![
        ("name".to_owned(), tool.tool.name.clone()),
        ("description".to_owned(), tool.tool.description.clone()),
    ];

    // Parameter names and descriptions are read by the model exactly like the
    // tool description is, so they are just as good a place to hide something.
    if let Some(input_schema) = tool.tool.input_schema.as_ref() {
        for param in schema::flatten(input_schema).iter() {
            out.push((format!("inputSchema.{}", param.path), param.name.clone()));
            if let Some(description) = &param.description {
                out.push((
                    format!("inputSchema.{}.description", param.path),
                    description.clone(),
                ));
            }
        }
    }

    out.retain(|(_, text)| !text.is_empty());
    out
}

/// The obfuscation analyser.
#[derive(Debug, Default, Clone, Copy)]
pub struct ObfuscationCheck;

impl ObfuscationCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ToolCheck for ObfuscationCheck {
    fn id(&self) -> &'static str {
        "obfuscation"
    }

    fn description(&self) -> &'static str {
        "Finds text that a human reviewer and a model do not read the same: \
         invisible characters, Unicode tag characters, bidi overrides, homoglyphs."
    }

    fn check(&self, tool: &ToolContext<'_>, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        let subject = tool.tool_ref();
        let mut findings = Vec::new();

        for (label, text) in fields(tool) {
            let normalized = normalize::normalize(&text);
            if normalized.is_clean() {
                continue;
            }
            // One finding per kind per field: a smuggled sentence is one
            // problem, not one per codepoint.
            for kind in normalized.kinds() {
                let notes: Vec<&NormalizationNote> = normalized.notes_of(kind).collect();
                findings.push(finding(&subject, &tool.tool.name, &label, kind, &notes));
            }
        }

        findings
    }
}

fn finding(
    subject: &ToolRef,
    tool_name: &str,
    field: &str,
    kind: NoteKind,
    notes: &[&NormalizationNote],
) -> Finding {
    let occurrences = notes.len();
    let codepoints: usize = notes.iter().map(|n| n.codepoints.len()).sum();

    let mut message = format!(
        "The `{field}` of `{tool_name}` contains {codepoints} {kind} codepoint(s) in \
         {occurrences} run(s); {}.",
        statement(kind)
    );

    // The decoded payload is the most useful thing the scanner can say.
    let decoded: Vec<&str> = notes
        .iter()
        .filter_map(|n| n.detail.as_deref())
        .take(3)
        .collect();
    if !decoded.is_empty() {
        message.push_str(&format!(" {}", decoded.join(" ")));
    }

    let mut builder = Finding::builder(
        finding_id(kind),
        Category::Obfuscation,
        severity(kind),
        format!("{}: `{field}`", title(kind)),
    )
    .message(message)
    .confidence(match kind {
        // The two kinds with a real false-positive story.
        NoteKind::MixedScript | NoteKind::EncodedPayload => Confidence::Medium,
        _ => Confidence::High,
    })
    .subject(subject.clone())
    .remediation(remediation(kind));

    for note in notes.iter().take(5) {
        let excerpt = match &note.detail {
            Some(detail) => detail.clone(),
            None => note.codepoints_display(),
        };
        builder = builder.evidence(
            Evidence::new(format!("{field} @ byte {}", note.offset), excerpt).with_span(
                crate::finding::Span::new(note.offset, note.offset + note.raw.len()),
            ),
        );
    }

    builder.build()
}
