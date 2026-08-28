//! Static tool enumeration.
//!
//! The load-bearing test in this file is `stdio_server_is_never_executed`: it
//! plants a config whose command would create a witness file if it ever ran,
//! runs the full pipeline, and asserts the file does not exist. That is the
//! guarantee the whole step rests on.

mod common;

use std::time::Duration;

use common::{
    dead_url, http_response, json_200, json_400, spawn_blackhole, spawn_mock, spawn_mock_req,
    spawn_sse_open_ended, TempDir,
};

use mcpwn::enumerate::{self, Enumeration, StaticEnumerator, PROTOCOL_VERSION};
use mcpwn::manifest::{ServerManifest, Transport};
use mcpwn::{discovery, loading};

// --- helpers ----------------------------------------------------------------

fn http_server(url: &str) -> ServerManifest {
    let mut server = ServerManifest::new("remote");
    server.transport = Some(Transport::Http {
        url: url.to_owned(),
    });
    server
}

fn fast() -> StaticEnumerator {
    StaticEnumerator::new().timeout(Duration::from_millis(700))
}

const TOOLS_RESULT: &str = r#"{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resultType": "complete",
    "ttlMs": 60000,
    "cacheScope": "public",
    "tools": [
      {
        "name": "read_file",
        "description": "Read a file from disk.",
        "inputSchema": {
          "type": "object",
          "properties": { "path": { "type": "string", "description": "Absolute path" } },
          "required": ["path"]
        }
      },
      {
        "name": "send_email",
        "description": "Send an email.",
        "inputSchema": { "type": "object", "properties": { "to": { "type": "string" } } },
        "annotations": { "destructiveHint": true }
      }
    ]
  }
}"#;

// --- the modern (2026-07-28) path -------------------------------------------

#[test]
fn modern_stateless_tools_list_is_parsed() {
    let url = spawn_mock(|body| {
        // The current revision has no initialize handshake: the very first
        // request is tools/list, carrying its version in _meta.
        assert!(body.contains("\"tools/list\""), "unexpected body: {body}");
        assert!(
            body.contains("io.modelcontextprotocol/protocolVersion"),
            "modern request must carry _meta: {body}"
        );
        assert!(!body.contains("\"initialize\""), "must not handshake first");
        json_200(TOOLS_RESULT)
    });

    let result = fast().enumerate(http_server(&url));

    assert_eq!(
        result.outcome,
        Enumeration::Enumerated {
            protocol: PROTOCOL_VERSION.to_owned()
        }
    );
    assert_eq!(result.tool_count(), 2);

    let read = &result.server.tools[0];
    assert_eq!(read.name, "read_file");
    assert_eq!(read.description, "Read a file from disk.");
    let schema = read.input_schema.as_ref().expect("input schema kept");
    assert_eq!(schema["properties"]["path"]["type"], "string");
    // Kept verbatim, including the per-parameter description the model reads.
    assert_eq!(schema["properties"]["path"]["description"], "Absolute path");

    // Unknown fields are preserved for later analysis rather than dropped.
    let email = &result.server.tools[1];
    assert_eq!(email.extra["annotations"]["destructiveHint"], true);
}

#[test]
fn an_sse_response_stream_is_parsed() {
    let url = spawn_mock(|_| {
        // Streamable HTTP lets the server answer with SSE instead of JSON; a
        // client MUST support both. Keep-alive comments must be ignored.
        let body = format!(
            ":\n\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\ndata: {}\n\n",
            TOOLS_RESULT.replace('\n', "")
        );
        http_response(200, "OK", "text/event-stream", &body)
    });

    let result = fast().enumerate(http_server(&url));

    assert!(result.outcome.is_enumerated(), "{:?}", result.outcome);
    assert_eq!(result.tool_count(), 2);
}

// --- backward compatibility -------------------------------------------------

#[test]
fn a_legacy_server_gets_the_initialize_handshake() {
    let url = spawn_mock(|body| {
        if body.contains("io.modelcontextprotocol/protocolVersion") {
            // Legacy server: a 400 with no recognisable modern error body.
            return http_response(400, "Bad Request", "text/plain", "");
        }
        if body.contains("\"initialize\"") {
            return json_200(
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"1"}}}"#,
            );
        }
        if body.contains("notifications/initialized") {
            return http_response(202, "Accepted", "text/plain", "");
        }
        json_200(&TOOLS_RESULT.replace("\"id\": 1", "\"id\": 2"))
    });

    let result = fast().enumerate(http_server(&url));

    assert_eq!(
        result.outcome,
        Enumeration::Enumerated {
            protocol: "2025-11-25".to_owned()
        }
    );
    assert_eq!(result.tool_count(), 2);
}

#[test]
fn unsupported_version_error_steers_to_a_version_the_server_supports() {
    let url = spawn_mock(|body| {
        if body.contains("io.modelcontextprotocol/protocolVersion") {
            // A *modern* error: the client must read the body and retry with an
            // advertised version instead of blindly falling back.
            return json_400(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2025-06-18"],"requested":"2026-07-28"}}}"#,
            );
        }
        if body.contains("\"initialize\"") {
            assert!(
                body.contains("2025-06-18"),
                "must use the advertised version"
            );
            return json_200(
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
            );
        }
        json_200(&TOOLS_RESULT.replace("\"id\": 1", "\"id\": 2"))
    });

    let result = fast().enumerate(http_server(&url));

    assert_eq!(
        result.outcome,
        Enumeration::Enumerated {
            protocol: "2025-06-18".to_owned()
        }
    );
}

// --- failure paths, none of which may panic ---------------------------------

#[test]
fn a_malformed_response_fails_cleanly() {
    let url = spawn_mock(|_| json_200("this is not json at all"));

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(result.tool_count(), 0);
}

#[test]
fn a_result_without_a_tools_field_fails_cleanly() {
    let url =
        spawn_mock(|_| json_200(r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}"#));

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => assert!(reason.contains("tools"), "got: {reason}"),
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn a_json_error_page_is_not_mistaken_for_a_json_rpc_error() {
    // A gateway rejecting the request answers with JSON that is *not* JSON-RPC.
    // Reported verbatim with its status, never as an empty protocol error.
    let url = spawn_mock(|_| {
        http_response(
            401,
            "Unauthorized",
            "application/json",
            r#"{"error":"Missing or invalid Authorization header. Use: Bearer mcp_xxx"}"#,
        )
    });

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => {
            assert!(reason.contains("HTTP 401"), "got: {reason}");
            assert!(reason.contains("requires authentication"), "got: {reason}");
            assert!(reason.contains("Authorization header"), "got: {reason}");
            assert!(!reason.contains("unspecified"), "got: {reason}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn an_authenticated_endpoint_does_not_trigger_a_legacy_fallback() {
    // 401 means the same thing in both protocol eras: retrying with `initialize`
    // only wastes requests.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let url = spawn_mock(move |_| {
        seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        http_response(
            401,
            "Unauthorized",
            "application/json",
            r#"{"error":"nope"}"#,
        )
    });

    let result = fast().enumerate(http_server(&url));

    assert!(matches!(result.outcome, Enumeration::Failed { .. }));
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "a 401 must not be retried across protocol eras"
    );
}

#[test]
fn an_html_error_page_is_summarised_not_quoted() {
    let url = spawn_mock(|_| {
        http_response(
            405,
            "Method Not Allowed",
            "text/html",
            "<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example</h1></body></html>",
        )
    });

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => {
            assert!(reason.contains("HTTP 405"), "got: {reason}");
            assert!(reason.contains("HTML page"), "got: {reason}");
            assert!(
                !reason.contains("doctype"),
                "the page must not be quoted: {reason}"
            );
            // A plain HTTP rejection is not a handshake failure.
            assert!(!reason.contains("initialize"), "got: {reason}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn a_wrong_path_is_reported_as_a_wrong_path() {
    let url = spawn_mock(|_| http_response(404, "Not Found", "text/plain", "Not Found"));

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => {
            assert!(reason.contains("HTTP 404"), "got: {reason}");
            assert!(reason.contains("no MCP endpoint"), "got: {reason}");
            assert!(!reason.starts_with("initialize"), "got: {reason}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn an_sse_endpoint_gets_a_hint_about_the_deprecated_transport() {
    let base = spawn_mock(|_| http_response(405, "Method Not Allowed", "text/plain", ""));
    let url = format!("{}/sse", base.trim_end_matches("/mcp"));

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => {
            assert!(reason.contains("HTTP+SSE"), "got: {reason}");
            assert!(reason.contains("/mcp"), "got: {reason}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn a_rejected_handshake_still_says_so() {
    // The `initialize` prefix is correct when the server *did* answer in
    // JSON-RPC and refused; it is only wrong for transport-level failures.
    let url = spawn_mock(|body| {
        if body.contains("io.modelcontextprotocol/protocolVersion") {
            return http_response(400, "Bad Request", "text/plain", "");
        }
        json_200(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad client"}}"#)
    });

    let result = fast().enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => {
            assert!(reason.contains("initialize rejected"), "got: {reason}");
            assert!(reason.contains("bad client"), "got: {reason}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn a_server_that_never_answers_times_out() {
    let url = spawn_blackhole();

    let result = StaticEnumerator::new()
        .timeout(Duration::from_millis(300))
        .enumerate(http_server(&url));

    match &result.outcome {
        Enumeration::Failed { reason } => {
            assert!(reason.contains("timed out"), "got: {reason}")
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn an_unreachable_server_fails_cleanly() {
    let result = fast().enumerate(http_server(&dead_url()));

    match &result.outcome {
        Enumeration::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn a_server_with_no_transport_is_not_enumerable() {
    let result = fast().enumerate(ServerManifest::new("headless"));

    match &result.outcome {
        Enumeration::NotPossible { reason } => assert!(reason.contains("transport")),
        other => panic!("expected NotPossible, got {other:?}"),
    }
}

// --- legacy sessions and open-ended streams ---------------------------------

#[test]
fn the_legacy_session_id_is_captured_and_replayed() {
    // Regression from a live scan of gitmcp.io: protocol revisions 2025-03-26
    // through 2025-11-25 mint a session on `initialize` and reject every later
    // request that does not carry it.
    const SESSION: &str = "sess-abc123";

    let url = spawn_mock_req(|request| {
        if request
            .body
            .contains("io.modelcontextprotocol/protocolVersion")
        {
            return json_400(
                r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Mcp-Session-Id header is required"},"id":null}"#,
            );
        }
        if request.body.contains("\"initialize\"") {
            return http_response(
                200,
                "OK",
                "application/json",
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}"#,
            )
            .replace(
                "content-type: application/json",
                &format!("content-type: application/json\r\nmcp-session-id: {SESSION}"),
            );
        }
        // Every later request must carry the session the server minted.
        if !request.has_header("mcp-session-id", SESSION) {
            return json_400(
                r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Mcp-Session-Id header is required"},"id":null}"#,
            );
        }
        json_200(&TOOLS_RESULT.replace("\"id\": 1", "\"id\": 2"))
    });

    let result = fast().enumerate(http_server(&url));

    assert!(result.outcome.is_enumerated(), "{:?}", result.outcome);
    assert_eq!(result.tool_count(), 2);
}

#[test]
fn an_sse_stream_that_never_closes_does_not_hang_the_scan() {
    // The spec only says the final response *SHOULD* end the stream. Reading to
    // EOF here would block until the global timeout even though the answer has
    // already arrived.
    let url = spawn_sse_open_ended(TOOLS_RESULT.to_owned());

    let started = std::time::Instant::now();
    let result = StaticEnumerator::new()
        .timeout(Duration::from_secs(10))
        .enumerate(http_server(&url));
    let elapsed = started.elapsed();

    assert!(result.outcome.is_enumerated(), "{:?}", result.outcome);
    assert_eq!(result.tool_count(), 2);
    assert!(
        elapsed < Duration::from_secs(5),
        "the scan waited for a stream that never ends: {elapsed:?}"
    );
}

// --- direct endpoint entry -------------------------------------------------

#[test]
fn a_url_produces_the_same_server_as_a_config_would() {
    let url = spawn_mock(|_| json_200(TOOLS_RESULT));

    // Built from a bare URL...
    let from_url = enumerate::server_from_url(&url).expect("valid endpoint");
    // ...and built the way loading builds one out of a config file.
    let from_config = http_server(&url);

    assert_eq!(from_url.transport, from_config.transport);

    let direct = fast().enumerate(from_url);
    let via_config = fast().enumerate(from_config);

    // Same code path, so: same outcome, same tools.
    assert_eq!(direct.outcome, via_config.outcome);
    assert!(direct.outcome.is_enumerated(), "{:?}", direct.outcome);
    assert_eq!(direct.tool_count(), 2);
    assert_eq!(
        direct
            .server
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.description.as_str()))
            .collect::<Vec<_>>(),
        via_config
            .server
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.description.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_url_gets_a_readable_server_name_and_origin() {
    let server = enumerate::server_from_url("https://example.com/mcp/").expect("valid");
    assert_eq!(server.name, "example.com/mcp");
    assert_eq!(server.origin.as_deref(), Some("https://example.com/mcp/"));
}

#[test]
fn invalid_urls_are_rejected_without_panicking() {
    for (url, expected) in [
        ("not-a-url", "http"),
        ("example.com/mcp", "http"),
        ("file:///etc/passwd", "http"),
        ("ftp://example.com", "http"),
        ("http://", "host"),
        ("https://", "host"),
        ("", "empty"),
        ("   ", "empty"),
        ("http://exa mple.com/mcp", "whitespace"),
    ] {
        let err = enumerate::server_from_url(url)
            .expect_err(&format!("`{url}` must be rejected"))
            .to_string();
        assert!(
            err.contains(expected),
            "`{url}`: expected the error to mention `{expected}`, got: {err}"
        );
    }
}

#[test]
fn valid_urls_are_accepted() {
    for url in [
        "http://localhost:3000/mcp",
        "https://example.com/mcp",
        "https://example.com",
        "HTTPS://Example.COM/mcp",
        "https://user:pass@example.com/mcp",
        "https://example.com/mcp?tenant=x",
    ] {
        enumerate::server_from_url(url).unwrap_or_else(|e| panic!("`{url}` must be accepted: {e}"));
    }
}

// --- authentication headers -------------------------------------------------

#[test]
fn a_header_reaches_the_server_and_unlocks_an_authenticated_endpoint() {
    let url = spawn_mock_req(|request| {
        if !request.has_header("authorization", "Bearer s3cret") {
            return http_response(
                401,
                "Unauthorized",
                "application/json",
                r#"{"error":"Missing or invalid Authorization header"}"#,
            );
        }
        json_200(TOOLS_RESULT)
    });

    // Without the header: refused, and said so clearly.
    let refused = fast().enumerate(http_server(&url));
    assert!(matches!(refused.outcome, Enumeration::Failed { .. }));

    // With it: the same endpoint enumerates.
    let allowed = fast()
        .headers(vec![(
            "Authorization".to_owned(),
            "Bearer s3cret".to_owned(),
        )])
        .enumerate(http_server(&url));

    assert!(allowed.outcome.is_enumerated(), "{:?}", allowed.outcome);
    assert_eq!(allowed.tool_count(), 2);
}

#[test]
fn several_headers_are_all_sent() {
    let url = spawn_mock_req(|request| {
        assert!(
            request.has_header("authorization", "Bearer s3cret"),
            "headers seen:\n{}",
            request.headers
        );
        assert!(
            request.has_header("x-tenant", "acme"),
            "headers seen:\n{}",
            request.headers
        );
        assert!(
            request.has_header("x-trace", "42"),
            "headers seen:\n{}",
            request.headers
        );
        // The protocol headers mcpwn owns must still be intact.
        assert!(request.has_header("mcp-method", "tools/list"));
        json_200(TOOLS_RESULT)
    });

    let headers = enumerate::parse_headers(&[
        "Authorization: Bearer s3cret",
        "X-Tenant: acme",
        "X-Trace: 42",
    ])
    .expect("valid headers");

    let result = fast().headers(headers).enumerate(http_server(&url));

    assert!(result.outcome.is_enumerated(), "{:?}", result.outcome);
}

#[test]
fn headers_are_sent_on_the_legacy_path_too() {
    let url = spawn_mock_req(|request| {
        assert!(
            request.has_header("authorization", "Bearer s3cret"),
            "the handshake must be authenticated too:\n{}",
            request.headers
        );
        if request
            .body
            .contains("io.modelcontextprotocol/protocolVersion")
        {
            return http_response(400, "Bad Request", "text/plain", "");
        }
        if request.body.contains("\"initialize\"") {
            return json_200(
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}"#,
            );
        }
        json_200(&TOOLS_RESULT.replace("\"id\": 1", "\"id\": 2"))
    });

    let result = fast()
        .headers(vec![(
            "Authorization".to_owned(),
            "Bearer s3cret".to_owned(),
        )])
        .enumerate(http_server(&url));

    assert!(result.outcome.is_enumerated(), "{:?}", result.outcome);
}

#[test]
fn header_parsing_accepts_the_shapes_people_actually_type() {
    for (raw, name, value) in [
        ("Authorization: Bearer abc", "Authorization", "Bearer abc"),
        ("Authorization:Bearer abc", "Authorization", "Bearer abc"),
        ("  X-Api-Key :   k1  ", "X-Api-Key", "k1"),
        // A value containing a colon must survive intact.
        ("X-Url: https://x.test/a", "X-Url", "https://x.test/a"),
    ] {
        let parsed = enumerate::parse_header(raw).unwrap_or_else(|e| panic!("`{raw}`: {e}"));
        assert_eq!(parsed, (name.to_owned(), value.to_owned()), "`{raw}`");
    }
}

#[test]
fn bad_headers_are_rejected_and_never_echo_the_value() {
    let cases = [
        ("no-colon-here", "Name: Value"),
        (": novalue", "name is empty"),
        ("Authorization:", "value is empty"),
        ("Bad Name: x", "not allowed"),
        ("Bad(Name): x", "not allowed"),
        // Protocol headers mcpwn owns.
        ("content-type: application/xml", "cannot be overridden"),
        ("MCP-Protocol-Version: 1999-01-01", "cannot be overridden"),
        // Header injection.
        ("X-Tok: a\r\nX-Evil: yes", "control characters"),
    ];

    for (raw, expected) in cases {
        let err = enumerate::parse_header(raw)
            .expect_err(&format!("`{raw}` must be rejected"))
            .to_string();
        assert!(err.contains(expected), "`{raw}`: got `{err}`");
    }

    // The secret must never end up in an error message.
    let err = enumerate::parse_header("Authorization: Bearer sup3rs3cret\r\nX-Evil: 1")
        .expect_err("rejected")
        .to_string();
    assert!(!err.contains("sup3rs3cret"), "the token leaked: {err}");
}

// --- THE safety guarantee ---------------------------------------------------

#[test]
fn stdio_server_is_never_executed() {
    let tmp = TempDir::new("no-exec");
    let witness = tmp.path().join("PWNED");
    let control = tmp.path().join("CONTROL");

    // Sanity check first: prove the witness mechanism actually works, so that a
    // missing file below means "we did not run it", not "the command was a dud".
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("touch '{}'", control.display()))
        .status()
        .expect("run the control command");
    assert!(status.success());
    assert!(control.exists(), "the witness command must work when run");

    let config = format!(
        r#"{{"mcpServers": {{"evil": {{"command": "/bin/sh", "args": ["-c", "touch '{}'"]}}}}}}"#,
        witness.display()
    );
    tmp.write(".cursor/mcp.json", &config);

    // The full pipeline: discover -> load -> enumerate.
    let configs = discovery::discover_project(tmp.path());
    let loaded = loading::load_all(&configs);
    let servers = StaticEnumerator::new().enumerate_all(loading::servers_of(&loaded));

    assert_eq!(servers.len(), 1);
    match &servers[0].outcome {
        Enumeration::NotPossible { reason } => {
            assert!(reason.contains("stdio"), "got: {reason}")
        }
        other => panic!("a stdio server must never be enumerated, got {other:?}"),
    }
    assert_eq!(servers[0].tool_count(), 0);

    // A spawned process could finish asynchronously; give it every chance to
    // betray itself before we declare victory.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !witness.exists(),
        "SAFETY VIOLATION: the stdio server's command was executed"
    );
}

#[test]
fn a_stdio_server_is_not_a_warning() {
    let mut server = ServerManifest::new("local");
    server.transport = Some(Transport::Stdio {
        command: "npx".to_owned(),
        args: vec!["-y".to_owned(), "some-mcp".to_owned()],
        env: Default::default(),
    });

    let enumerated = StaticEnumerator::new().enumerate_all(vec![server]);

    assert!(matches!(
        enumerated[0].outcome,
        Enumeration::NotPossible { .. }
    ));
    // Not being able to enumerate a stdio server is the intended behaviour, so
    // it must not surface as a warning.
    assert!(mcpwn::output::inventory::enumeration_warnings(&enumerated).is_empty());
}
