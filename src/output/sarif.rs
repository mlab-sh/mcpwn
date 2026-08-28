//! SARIF 2.1.0 serialisation, for CI and the future GitHub Action.
//!
//! Only the envelope is built today: the run, the tool descriptor and an empty
//! `results` array. Mapping [`Finding`]s onto SARIF results (rule descriptors,
//! `level`, physical locations from [`crate::finding::Span`]) comes with the
//! detection modules.

use serde_json::{json, Value};

use crate::finding::{Finding, Severity};
use crate::report::Report;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

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
                    "informationUri": "https://github.com/Sn0wAlice/mcpwn",
                    // TODO: one reportingDescriptor per rule id once rules exist.
                    "rules": [],
                }
            },
            "results": report.findings.iter().map(to_result).collect::<Vec<_>>(),
        }]
    })
}

pub fn to_sarif_string(report: &Report) -> crate::Result<String> {
    Ok(serde_json::to_string_pretty(&to_sarif(report))?)
}

/// Map one finding onto a SARIF `result` object.
fn to_result(finding: &Finding) -> Value {
    json!({
        "ruleId": finding.id.as_str(),
        "level": sarif_level(finding.severity),
        "message": { "text": if finding.message.is_empty() {
            finding.title.clone()
        } else {
            finding.message.clone()
        }},
        // TODO: physicalLocation from the manifest path + Evidence::span,
        // and codeFlows from Finding::flow for toxic-flow findings.
        "locations": [],
    })
}

/// SARIF only has four levels; `Info` and `Low` both collapse to `note`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
