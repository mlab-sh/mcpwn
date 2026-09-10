//! The two model-visible surfaces that are not tools.
//!
//! An MCP server advertises three things, not one. Tools get all the attention
//! because they *act*, but prompts and resources are read by the model just as
//! literally:
//!
//! * A **prompt** is expanded into the conversation, usually because the user
//!   picked it from a menu and therefore trusts it. Its description and its
//!   argument descriptions are prose the model follows.
//! * A **resource** is fetched and dropped into the context. Its description
//!   and URI are shown to the model when it decides what to read.
//!
//! So every trick that hides an instruction in a tool description works here
//! too, against a surface a reviewer is less likely to have read. This check
//! runs the same normalisation over both and reports through
//! [`super::obfuscation`], reusing its rule ids: a zero-width payload is the
//! same defect wherever it is found, and splitting the catalogue by location
//! would only make it harder to look up.
//!
//! What this check does **not** do is fetch a resource. `resources/read`
//! returns attacker-chosen content and is a live interaction; only
//! `mcpwn audit` does that kind of thing, and only under an engagement file.

use crate::analysis::check::{ScanContext, ServerCheck};
use crate::analysis::normalize::{self, NormalizationNote};
use crate::analysis::obfuscation;
use crate::finding::Finding;
use crate::manifest::{PromptManifest, ResourceManifest, ServerManifest, ToolRef};

/// Every model-visible string of one prompt, with a label for the finding.
///
/// Labels are relative to the prompt because the finding's subject already
/// names it, which keeps them readable next to the tool ones.
fn prompt_fields(prompt: &PromptManifest) -> Vec<(String, String)> {
    let mut out = vec![
        ("name".to_owned(), prompt.name.clone()),
        ("description".to_owned(), prompt.description.clone()),
    ];
    if let Some(title) = &prompt.title {
        out.push(("title".to_owned(), title.clone()));
    }

    // An argument description is prose the model reads while filling the
    // argument in, exactly like a tool parameter description.
    for argument in &prompt.arguments {
        out.push((
            format!("arguments.{}", argument.name),
            argument.name.clone(),
        ));
        if let Some(description) = &argument.description {
            out.push((
                format!("arguments.{}.description", argument.name),
                description.clone(),
            ));
        }
    }

    out.retain(|(_, text)| !text.is_empty());
    out
}

/// Every model-visible string of one resource.
///
/// The URI is in the list and not merely as an identifier: a look-alike
/// hostname or an invisible character in a path is how one resource is made to
/// pass for another.
fn resource_fields(resource: &ResourceManifest) -> Vec<(String, String)> {
    let mut out = vec![
        (
            if resource.template {
                "uriTemplate"
            } else {
                "uri"
            }
            .to_owned(),
            resource.uri.clone(),
        ),
        ("name".to_owned(), resource.name.clone()),
        ("description".to_owned(), resource.description.clone()),
    ];
    if let Some(title) = &resource.title {
        out.push(("title".to_owned(), title.clone()));
    }
    if let Some(mime_type) = &resource.mime_type {
        out.push(("mimeType".to_owned(), mime_type.clone()));
    }

    out.retain(|(_, text)| !text.is_empty());
    out
}

/// The prompt and resource analyser.
#[derive(Debug, Default, Clone, Copy)]
pub struct SurfaceCheck;

impl SurfaceCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ServerCheck for SurfaceCheck {
    fn id(&self) -> &'static str {
        "surface"
    }

    fn description(&self) -> &'static str {
        "Finds hidden text in the prompts and resources a server advertises, the \
         model-visible surfaces that are not tools."
    }

    fn check(&self, server: &ServerManifest, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for prompt in &server.prompts {
            findings.extend(scan(
                &server.prompt_ref(prompt),
                &format!("prompt `{}`", prompt.name),
                prompt_fields(prompt),
            ));
        }

        for resource in &server.resources {
            let what = if resource.template {
                "resource template"
            } else {
                "resource"
            };
            findings.extend(scan(
                &server.resource_ref(resource),
                &format!("{what} `{}`", resource.uri),
                resource_fields(resource),
            ));
        }

        findings
    }
}

/// Normalise every field and turn whatever it reports into findings.
fn scan(subject: &ToolRef, owner: &str, fields: Vec<(String, String)>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (label, text) in fields {
        let normalized = normalize::normalize(&text);
        if normalized.is_clean() {
            continue;
        }
        // One finding per kind per field, on the same reasoning as the tool
        // path: a smuggled sentence is one problem, not one per codepoint.
        for kind in normalized.kinds() {
            let notes: Vec<&NormalizationNote> = normalized.notes_of(kind).collect();
            findings.push(obfuscation::note_finding(
                subject, owner, &label, kind, &notes,
            ));
        }
    }
    findings
}
