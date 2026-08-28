//! Proves the whole chain compiles and the report model round-trips:
//! Analyzer -> Report -> JSON/SARIF. No detection logic is exercised.

use mcpwn::{Analyzer, Report, ServerManifest};

#[test]
fn empty_scan_produces_an_empty_report() {
    let servers: Vec<ServerManifest> = Vec::new();
    let report = Analyzer::new().analyze(&servers);

    assert!(report.is_empty());
    assert_eq!(report.meta.servers, 0);
    assert_eq!(report.meta.tools, 0);
    assert_eq!(report.max_severity(), None);
}

#[test]
fn report_serializes_and_deserializes() {
    let report = Analyzer::new().analyze(&[]);

    let json = report.to_json().expect("report serializes to json");
    let back: Report = serde_json::from_str(&json).expect("report deserializes");

    assert_eq!(report, back);
}

#[test]
fn report_counts_the_manifests_it_was_given() {
    let mut server = ServerManifest::new("files");
    server.tools.push(mcpwn::ToolManifest::new("read_file"));
    server.tools.push(mcpwn::ToolManifest::new("write_file"));

    let report = Analyzer::new().analyze(&[server]);

    assert_eq!(report.meta.servers, 1);
    assert_eq!(report.meta.tools, 2);
    assert!(report.is_empty(), "no detection module is implemented yet");
}

#[test]
fn empty_report_serializes_to_valid_sarif() {
    let report = Analyzer::new().analyze(&[]);
    let sarif = mcpwn::output::sarif::to_sarif(&report);

    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], mcpwn::NAME);
    assert_eq!(
        sarif["runs"][0]["results"].as_array().map(Vec::len),
        Some(0)
    );
}
