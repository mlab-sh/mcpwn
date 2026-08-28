//! The read-only reconnaissance pass and the checks that read it.
//!
//! Everything here runs against local mocks. That matters more than usual: the
//! probe is the only part of mcpwn that sends requests the user did not ask
//! for, so what it concludes has to be pinned rather than observed once against
//! a live server and assumed.

mod common;

use std::process::{Command, Output};

use common::{http_response, json_200, spawn_mock_req, MockRequest};

use mcpwn::analysis::check::{ScanContext, ServerCheck};
use mcpwn::analysis::network::NetworkCheck;
use mcpwn::finding::{Finding, Severity};
use mcpwn::manifest::{ServerManifest, Transport};
use mcpwn::recon::{self, Prober, ServerProbe};

fn mcpwn(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcpwn"))
        .args(args)
        .output()
        .expect("run the mcpwn binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

const TOOLS: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {"name":"read_file","description":"Reads a file.","inputSchema":{"type":"object"}}]}}"#;

const UNSUPPORTED_VERSION: &str = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,
  "message":"Unsupported protocol version","data":{"supported":["2026-07-28"]}}}"#;

const HEADER_MISMATCH: &str = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020,
  "message":"Header mismatch"}}"#;

/// A well-behaved server: validates the version and the mirrored headers.
fn strict(request: &MockRequest) -> Option<String> {
    if request
        .headers
        .to_lowercase()
        .contains("mcp-protocol-version: 1900-01-01")
    {
        return Some(http_response(
            400,
            "Bad Request",
            "application/json",
            UNSUPPORTED_VERSION,
        ));
    }
    if request
        .headers
        .to_lowercase()
        .contains("mcp-method: tools/call")
        && request.body.contains("tools/list")
    {
        return Some(http_response(
            400,
            "Bad Request",
            "application/json",
            HEADER_MISMATCH,
        ));
    }
    None
}

fn probe_of(url: &str) -> ServerProbe {
    Prober::new().probe(url)
}

fn findings(server: &ServerManifest, probe: &ServerProbe) -> Vec<Finding> {
    let servers = [server.clone()];
    let probes = [probe.clone()];
    let ctx = ScanContext::new(&servers).with_probes(&probes);
    NetworkCheck::new().check(server, &ctx)
}

fn http(url: &str) -> ServerManifest {
    let mut server = ServerManifest::new("remote");
    server.transport = Some(Transport::Http {
        url: url.to_owned(),
    });
    server
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    let mut out: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    out.sort_unstable();
    out
}

// --- a server that does everything right ------------------------------------

#[test]
fn a_well_behaved_server_produces_no_findings() {
    let url = spawn_mock_req(|request| strict(&request).unwrap_or_else(|| json_200(TOOLS)));

    let probe = probe_of(&url);
    assert_eq!(probe.accepts_impossible_version, Some(false));
    assert_eq!(probe.accepts_header_mismatch, Some(false));
    assert!(findings(&http(&url), &probe).is_empty(), "{probe:#?}");
}

// --- the two specification MUSTs --------------------------------------------

#[test]
fn a_server_that_ignores_the_protocol_version_is_reported() {
    // Answers anything, whatever version it is told.
    let url = spawn_mock_req(|_| json_200(TOOLS));

    let probe = probe_of(&url);
    assert_eq!(probe.accepts_impossible_version, Some(true));

    let found = findings(&http(&url), &probe);
    assert!(
        found.iter().any(|f| f.id.as_str() == "MCPWN-NET-005"),
        "{found:#?}"
    );
    let finding = found
        .iter()
        .find(|f| f.id.as_str() == "MCPWN-NET-005")
        .unwrap();
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.server.as_deref(), Some("remote"));
}

#[test]
fn a_server_that_ignores_header_body_disagreement_is_reported() {
    // Validates the version, but not the mirrored headers.
    let url = spawn_mock_req(|request| {
        if request
            .headers
            .to_lowercase()
            .contains("mcp-protocol-version: 1900-01-01")
        {
            return http_response(400, "Bad Request", "application/json", UNSUPPORTED_VERSION);
        }
        json_200(TOOLS)
    });

    let probe = probe_of(&url);
    assert_eq!(probe.accepts_impossible_version, Some(false));
    assert_eq!(probe.accepts_header_mismatch, Some(true));
    assert_eq!(ids(&findings(&http(&url), &probe)), vec!["MCPWN-NET-006"]);
}

// --- authentication ---------------------------------------------------------

#[test]
fn a_credential_the_server_does_not_require_is_reported() {
    // Answers everyone, credential or not.
    let url = spawn_mock_req(|request| strict(&request).unwrap_or_else(|| json_200(TOOLS)));

    let probe = Prober::new()
        .headers(vec![("Authorization".to_owned(), "Bearer x".to_owned())])
        .probe(&url);

    assert_eq!(probe.anonymous_tools_list, Some(true));
    assert!(probe.credentials_supplied);
    assert_eq!(ids(&findings(&http(&url), &probe)), vec!["MCPWN-NET-001"]);
}

#[test]
fn an_open_server_is_not_reported_when_no_credential_was_supplied() {
    // The anti-false-positive that matters: every public documentation server
    // answers anonymously, and none of them is a finding.
    let url = spawn_mock_req(|request| strict(&request).unwrap_or_else(|| json_200(TOOLS)));

    let probe = probe_of(&url);
    assert_eq!(probe.anonymous_tools_list, Some(true));
    assert!(!probe.credentials_supplied);
    assert!(
        !ids(&findings(&http(&url), &probe)).contains(&"MCPWN-NET-001"),
        "an open server is not a finding on its own"
    );
}

#[test]
fn a_server_that_enforces_its_credential_is_not_reported() {
    let url = spawn_mock_req(|request| {
        if !request.has_header("authorization", "Bearer x") {
            return http_response(
                401,
                "Unauthorized",
                "application/json",
                r#"{"error":"unauthorized"}"#,
            )
            .replace(
                "content-type: application/json",
                "content-type: application/json\r\nwww-authenticate: Bearer resource_metadata=\"https://x/.well-known/oauth-protected-resource\"",
            );
        }
        strict(&request).unwrap_or_else(|| json_200(TOOLS))
    });

    let probe = Prober::new()
        .headers(vec![("Authorization".to_owned(), "Bearer x".to_owned())])
        .probe(&url);

    assert_eq!(probe.anonymous_tools_list, Some(false));
    assert!(probe.www_authenticate.is_some());
    assert!(findings(&http(&url), &probe).is_empty(), "{probe:#?}");
}

#[test]
fn a_protected_server_that_says_nothing_about_how_to_authenticate_is_reported() {
    let url = spawn_mock_req(|_| {
        http_response(
            401,
            "Unauthorized",
            "application/json",
            r#"{"error":"nope"}"#,
        )
    });

    let probe = probe_of(&url);
    assert_eq!(probe.anonymous_status, Some(401));
    assert!(probe.www_authenticate.is_none());
    assert_eq!(ids(&findings(&http(&url), &probe)), vec!["MCPWN-NET-002"]);
    assert_eq!(findings(&http(&url), &probe)[0].severity, Severity::Low);
}

// --- what else is on the origin ---------------------------------------------

#[test]
fn a_live_sse_endpoint_is_reported_as_the_deprecated_transport() {
    let url = spawn_mock_req(|request| {
        if request.headers.starts_with("GET /sse") {
            return http_response(
                200,
                "OK",
                "text/event-stream",
                "event: endpoint\ndata: /msg\n\n",
            );
        }
        strict(&request).unwrap_or_else(|| json_200(TOOLS))
    });

    let probe = probe_of(&url);
    assert!(probe.legacy_sse_endpoint.is_some(), "{probe:#?}");
    assert_eq!(ids(&findings(&http(&url), &probe)), vec!["MCPWN-NET-003"]);
}

#[test]
fn an_ordinary_page_at_slash_sse_is_not_the_legacy_transport() {
    // A 200 is not enough: the old transport answers with an event stream, and
    // anything else on that path is a different service.
    let url = spawn_mock_req(|request| {
        if request.headers.starts_with("GET /sse") {
            return http_response(200, "OK", "text/html", "<html>hello</html>");
        }
        strict(&request).unwrap_or_else(|| json_200(TOOLS))
    });

    let probe = probe_of(&url);
    assert!(probe.legacy_sse_endpoint.is_none(), "{probe:#?}");
}

#[test]
fn a_plaintext_endpoint_is_only_reported_when_it_speaks_the_protocol() {
    // Regression from a live scan: a filtering proxy answered on port 80 and
    // was read as an MCP endpoint. Answering HTTP is not the bar; answering
    // JSON-RPC is.
    let mut probe = ServerProbe {
        endpoint: "https://x.test/mcp".to_owned(),
        ..Default::default()
    };
    assert!(findings(&http("https://x.test/mcp"), &probe).is_empty());

    probe.plaintext_endpoint = Some("http://x.test/mcp".to_owned());
    let found = findings(&http("https://x.test/mcp"), &probe);
    assert_eq!(ids(&found), vec!["MCPWN-NET-004"]);
    assert_eq!(found[0].severity, Severity::High);
}

// --- the probe never breaks anything ----------------------------------------

#[test]
fn an_unreachable_endpoint_probes_to_nothing() {
    let probe = probe_of(&common::dead_url());

    assert!(probe.anonymous_status.is_none());
    assert!(probe.accepts_impossible_version.is_none());
    assert!(findings(&http("http://x.test/mcp"), &probe).is_empty());
}

#[test]
fn a_server_returning_nonsense_probes_to_nothing() {
    let url = spawn_mock_req(|_| http_response(200, "OK", "text/plain", "not json at all"));

    let probe = probe_of(&url);
    // Nothing could be concluded, so nothing is claimed.
    assert_eq!(probe.anonymous_tools_list, Some(false));
    assert!(probe.accepts_impossible_version.is_none());
    assert!(probe.accepts_header_mismatch.is_none());
}

#[test]
fn origin_is_extracted_without_the_path() {
    assert_eq!(
        recon::origin_of("https://x.test:8443/api/mcp?a=b"),
        Some("https://x.test:8443".to_owned())
    );
    assert_eq!(recon::origin_of("not-a-url"), None);
}

// --- the CLI ----------------------------------------------------------------

#[test]
fn probing_is_off_unless_asked_for() {
    let url = spawn_mock_req(|_| json_200(TOOLS));

    // The same server that fires NET-005 with --probe stays silent without it:
    // a plain scan must not start knocking on paths the user did not name.
    let quiet = stdout(&mcpwn(&["scan", "--url", &url, "--no-color"]));
    assert!(!quiet.contains("MCPWN-NET"), "{quiet}");

    let probing = stdout(&mcpwn(&["scan", "--url", &url, "--no-color", "--probe"]));
    assert!(probing.contains("MCPWN-NET-005"), "{probing}");
}

#[test]
fn view_probe_states_the_facts_without_judging_them() {
    let url = spawn_mock_req(|_| json_200(TOOLS));

    let out = stdout(&mcpwn(&["view", "--url", &url, "--no-color", "--probe"]));
    assert!(
        out.contains("answers tools/list with no credentials"),
        "{out}"
    );
    assert!(
        out.contains("does not validate the protocol version"),
        "{out}"
    );
    // `view` reports, it does not rule.
    assert!(!out.contains("MCPWN-"), "{out}");
}

#[test]
fn view_probe_json_carries_the_raw_observations() {
    let url = spawn_mock_req(|_| json_200(TOOLS));

    let output = mcpwn(&["view", "--url", &url, "--format", "json", "--probe"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid json");

    assert_eq!(parsed["probes"][0]["anonymous_tools_list"], true);
    assert_eq!(parsed["probes"][0]["accepts_impossible_version"], true);
}
