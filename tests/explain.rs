//! The rule catalogue behind `mcpwn explain`.
//!
//! The load-bearing test is `every_rule_the_checks_emit_is_documented` plus its
//! severity counterpart: documentation that silently drifts from the code is
//! worse than none, because it is trusted.

mod common;

use std::process::{Command, Output};

use mcpwn::analysis::capabilities::Capability;
use mcpwn::analysis::normalize::NoteKind;
use mcpwn::analysis::obfuscation;
use mcpwn::explain;

fn mcpwn(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcpwn"))
        .args(args)
        .output()
        .expect("run the mcpwn binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// --- the catalogue does not drift from the code -----------------------------

#[test]
fn every_rule_the_checks_emit_is_documented() {
    for capability in [
        Capability::CommandExecution,
        Capability::CodeEvaluation,
        Capability::FileAccess,
        Capability::NetworkAccess,
        Capability::HeaderSmuggling,
    ] {
        let id = capability.finding_id();
        assert!(
            explain::lookup(id).is_some(),
            "{id} is emitted but undocumented"
        );
    }

    for kind in NoteKind::ALL {
        let id = obfuscation::finding_id(kind);
        assert!(
            explain::lookup(id).is_some(),
            "{id} is emitted but undocumented"
        );
    }

    for id in [
        "MCPWN-RUG-001",
        "MCPWN-RUG-002",
        "MCPWN-RUG-003",
        "MCPWN-FLOW-001",
    ] {
        assert!(
            explain::lookup(id).is_some(),
            "{id} is emitted but undocumented"
        );
    }
}

#[test]
fn documented_severities_match_the_ones_actually_emitted() {
    for capability in [
        Capability::CommandExecution,
        Capability::CodeEvaluation,
        Capability::FileAccess,
        Capability::NetworkAccess,
        Capability::HeaderSmuggling,
    ] {
        let doc = explain::lookup(capability.finding_id()).expect("documented");
        assert_eq!(
            doc.severity,
            capability.base_severity(),
            "{} documents the wrong severity",
            doc.id
        );
    }

    for kind in NoteKind::ALL {
        let doc = explain::lookup(obfuscation::finding_id(kind)).expect("documented");
        assert_eq!(
            doc.severity,
            obfuscation::severity(kind),
            "{} documents the wrong severity",
            doc.id
        );
    }
}

#[test]
fn every_documented_rule_is_complete() {
    for rule in explain::all() {
        assert!(rule.id.starts_with("MCPWN-"), "{}", rule.id);
        assert!(!rule.title.is_empty(), "{}", rule.id);
        assert!(!rule.summary.is_empty(), "{}", rule.id);
        assert!(
            rule.detail.len() > 80,
            "{} has no real explanation",
            rule.id
        );
        assert!(!rule.remediation.is_empty(), "{}", rule.id);
        // The one that is easiest to skip and most useful to the reader.
        assert!(
            !rule.expected_noise.is_empty(),
            "{} does not say when it fires on something harmless",
            rule.id
        );
        assert!(!rule.check.is_empty(), "{}", rule.id);
    }
}

#[test]
fn rule_ids_are_unique() {
    let mut ids: Vec<&str> = explain::all().iter().map(|r| r.id).collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "duplicate rule id");
}

// --- lookup -----------------------------------------------------------------

#[test]
fn lookup_is_forgiving_about_case_and_the_prefix() {
    let canonical = explain::lookup("MCPWN-CAP-001").expect("found");
    for spelling in [
        "mcpwn-cap-001",
        "CAP-001",
        "cap-001",
        "  MCPWN-CAP-001  ",
        "Mcpwn-Cap-001",
    ] {
        let found =
            explain::lookup(spelling).unwrap_or_else(|| panic!("`{spelling}` should resolve"));
        assert_eq!(found.id, canonical.id, "`{spelling}`");
    }
}

#[test]
fn an_unknown_rule_is_not_found() {
    for unknown in ["MCPWN-XXX-999", "nonsense", "", "CAP-999"] {
        assert!(explain::lookup(unknown).is_none(), "`{unknown}`");
    }
}

// --- the CLI ----------------------------------------------------------------

#[test]
fn explaining_a_rule_prints_its_page() {
    let output = mcpwn(&["explain", "MCPWN-FLOW-001", "--no-color"]);
    let out = stdout(&output);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(out.contains("MCPWN-FLOW-001"), "{out}");
    assert!(out.contains("WHAT IT MEANS"), "{out}");
    assert!(out.contains("WHAT TO DO"), "{out}");
    assert!(out.contains("WHEN IT FIRES ON SOMETHING HARMLESS"), "{out}");
    // The vertical chain survives into the explanation.
    assert!(out.contains("ingest"), "{out}");
    assert!(out.contains("sink"), "{out}");
}

#[test]
fn explaining_without_an_id_lists_every_rule() {
    let output = mcpwn(&["explain", "--no-color"]);
    let out = stdout(&output);

    assert!(output.status.success(), "{}", stderr(&output));
    for rule in explain::all() {
        assert!(
            out.contains(rule.id),
            "{} missing from the index:\n{out}",
            rule.id
        );
    }
}

#[test]
fn explaining_an_unknown_rule_lists_the_known_ones() {
    let output = mcpwn(&["explain", "MCPWN-NOPE-001"]);
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(2));
    assert!(err.contains("no rule"), "{err}");
    // A dead end is useless; point at what does exist.
    assert!(err.contains("MCPWN-CAP-001"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn explain_json_is_machine_readable() {
    let output = mcpwn(&["explain", "cap-003", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));

    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");
    assert_eq!(parsed["id"], "MCPWN-CAP-003");
    assert_eq!(parsed["severity"], "high");
    assert_eq!(parsed["category"], "capability");

    // ...and the whole catalogue too.
    let all = mcpwn(&["explain", "--format", "json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&all)).expect("valid json");
    assert_eq!(parsed.as_array().map(Vec::len), Some(explain::all().len()));
}

#[test]
fn a_finding_id_from_a_real_scan_can_be_explained() {
    // The loop that matters: a user sees an id in a report and asks about it.
    let url = common::spawn_mock(|_| {
        common::json_200(
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
                 {"name":"shell","description":"Runs a command.",
                  "inputSchema":{"type":"object","properties":{"command":{"type":"string"}}}}
               ]}}"#,
        )
    });

    let scan = mcpwn(&["scan", "--url", &url, "--no-color"]);
    let report = stdout(&scan);

    let id = report
        .split_whitespace()
        .find(|word| word.starts_with("MCPWN-"))
        .expect("the report names a rule id");

    let explained = mcpwn(&["explain", id, "--no-color"]);
    assert!(
        explained.status.success(),
        "explaining `{id}`: {}",
        stderr(&explained)
    );
    assert!(stdout(&explained).contains(id), "{}", stdout(&explained));
}
