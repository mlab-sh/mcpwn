//! SARIF 2.1.0, for CI and the GitHub Action.
//!
//! The rule descriptors are generated from [`crate::explain`], so a finding in
//! GitHub's code-scanning UI carries the same explanation as
//! `mcpwn explain <ID>`: one source of truth, and no second copy to drift.
//!
//! Toxic-flow findings become SARIF `codeFlows`, which GitHub renders as an
//! ordered, clickable chain: the ingest → source → sink sequence survives into
//! the web UI instead of collapsing to one line of text.

use serde_json::{json, Map, Value};

use crate::explain::{self, RuleDoc};
use crate::finding::{Finding, Severity};
use crate::report::Report;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/mlab-sh/mcpwn";

/// Build a complete SARIF log for a report.
pub fn to_sarif(report: &Report) -> Value {
    json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": crate::NAME,
                    "version": crate::VERSION,
                    "semanticVersion": crate::VERSION,
                    "informationUri": INFORMATION_URI,
                    "rules": explain::all().iter().map(rule_descriptor).collect::<Vec<_>>(),
                }
            },
            "automationDetails": {
                "id": format!("mcpwn/{}", report.meta.target.as_deref().unwrap_or("scan")),
            },
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": [],
            }],
            "properties": {
                "servers": report.meta.servers,
                "tools": report.meta.tools,
                "target": report.meta.target,
            },
            "results": report.findings.iter().map(to_result).collect::<Vec<_>>(),
        }]
    })
}

pub fn to_sarif_string(report: &Report) -> crate::Result<String> {
    Ok(serde_json::to_string_pretty(&to_sarif(report))?)
}

/// One `reportingDescriptor`, straight from the rule catalogue.
fn rule_descriptor(rule: &RuleDoc) -> Value {
    json!({
        "id": rule.id,
        "name": pascal_case(rule.title),
        "shortDescription": { "text": rule.summary },
        "fullDescription": { "text": rule.detail },
        "help": {
            "text": format!("{}\n\nWhat to do: {}\n\nWhen it fires on something harmless: {}",
                rule.detail, rule.remediation, rule.expected_noise),
            "markdown": help_markdown(rule),
        },
        "defaultConfiguration": { "level": sarif_level(rule.severity) },
        "properties": {
            "category": rule.category.slug(),
            "check": rule.check,
            "severity": rule.severity.slug(),
            // GitHub surfaces these as filterable tags.
            "tags": ["mcp", "security", rule.category.slug()],
            "problem.severity": problem_severity(rule.severity),
        }
    })
}

fn help_markdown(rule: &RuleDoc) -> String {
    let mut out = format!("## {}\n\n{}\n", rule.title, rule.detail);
    if let Some(example) = rule.example {
        out.push_str(&format!("\n### Example\n\n```\n{example}\n```\n"));
    }
    out.push_str(&format!("\n### What to do\n\n{}\n", rule.remediation));
    out.push_str(&format!(
        "\n### When it fires on something harmless\n\n{}\n",
        rule.expected_noise
    ));
    out
}

/// One `result`.
fn to_result(finding: &Finding) -> Value {
    let mut result = Map::new();
    result.insert("ruleId".into(), json!(finding.id.as_str()));
    result.insert("level".into(), json!(sarif_level(finding.severity)));
    result.insert(
        "message".into(),
        json!({ "text": if finding.message.is_empty() { finding.title.clone() } else { finding.message.clone() } }),
    );
    result.insert("locations".into(), json!(locations(finding)));

    // A stable identity so code scanning can track a finding across runs
    // instead of reopening it every time the report is regenerated.
    result.insert(
        "partialFingerprints".into(),
        json!({ "mcpwnFindingV1": fingerprint(finding) }),
    );

    let mut properties = Map::new();
    properties.insert("category".into(), json!(finding.category.slug()));
    properties.insert("severity".into(), json!(finding.severity.slug()));
    properties.insert(
        "confidence".into(),
        json!(format!("{:?}", finding.confidence).to_lowercase()),
    );
    if let Some(scope) = finding.scope() {
        properties.insert("scope".into(), json!(scope));
    }
    if let Some(remediation) = &finding.remediation {
        properties.insert("remediation".into(), json!(remediation));
    }
    if !finding.evidence.is_empty() {
        properties.insert(
            "evidence".into(),
            json!(finding
                .evidence
                .iter()
                .map(|e| json!({ "label": e.label, "excerpt": e.excerpt }))
                .collect::<Vec<_>>()),
        );
    }
    result.insert("properties".into(), Value::Object(properties));

    // An ordered chain renders as a clickable code flow.
    if let Some(flow) = &finding.flow {
        result.insert(
            "codeFlows".into(),
            json!([{
                "message": { "text": "Exfiltration chain" },
                "threadFlows": [{
                    "locations": flow.steps.iter().map(|step| json!({
                        "location": {
                            "message": {
                                "text": format!("{}: {}{}", step.role, step.tool,
                                    step.note.as_deref().map(|n| format!("; {n}")).unwrap_or_default())
                            },
                            "physicalLocation": artifact_location(&step.tool.server),
                        }
                    })).collect::<Vec<_>>()
                }]
            }]),
        );
    }

    Value::Object(result)
}

/// Where a finding points.
///
/// mcpwn analyses live servers, not source files, so there is rarely a line to
/// point at. The honest location is the artefact the server was declared in,
/// the config file when it came from one, the endpoint URL when it did not.
fn locations(finding: &Finding) -> Vec<Value> {
    let scope = finding
        .scope()
        .unwrap_or_else(|| "(environment)".to_owned());
    let server = finding
        .subjects
        .first()
        .map(|s| s.server.clone())
        .or_else(|| finding.server.clone())
        .unwrap_or_else(|| "(environment)".to_owned());

    let mut location = artifact_location(&server);
    if let Some(span) = finding.evidence.iter().find_map(|e| e.span) {
        location["region"] = json!({
            "byteOffset": span.start,
            "byteLength": span.end.saturating_sub(span.start),
        });
    }

    vec![json!({
        "physicalLocation": location,
        "logicalLocations": [{ "fullyQualifiedName": scope, "kind": "member" }],
    })]
}

fn artifact_location(server: &str) -> Value {
    json!({
        "artifactLocation": {
            "uri": uri_for(server),
            "uriBaseId": "%SRCROOT%",
        }
    })
}

/// A URI SARIF will accept for a server identity.
fn uri_for(server: &str) -> String {
    if server.starts_with("http://") || server.starts_with("https://") {
        return server.to_owned();
    }
    // Not a path and not a URL: keep it readable and unambiguous.
    format!("mcp-server/{}", server.replace(' ', "-"))
}

/// Stable across runs, distinct per (rule, scope, title).
fn fingerprint(finding: &Finding) -> String {
    let scope = finding.scope().unwrap_or_default();
    format!("{}:{}:{}", finding.id, scope, finding.title)
}

/// SARIF has four levels; `Low` and `Info` both collapse to `note`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub reads this property to rank alerts, and it has its own vocabulary.
fn problem_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "recommendation",
    }
}

/// `Command execution` -> `CommandExecution`, for the SARIF rule `name` field.
fn pascal_case(title: &str) -> String {
    title
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}
