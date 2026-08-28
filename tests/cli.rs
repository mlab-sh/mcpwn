//! End-to-end CLI behaviour, driving the real binary.
//!
//! These are the only tests that exercise clap itself, which is where the
//! `--url` / PATH exclusivity is enforced.

mod common;

use std::process::{Command, Output};

use common::{http_response, json_200, spawn_mock, spawn_mock_req, TempDir};

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

const TOOLS_RESULT: &str = r#"{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resultType": "complete",
    "tools": [
      { "name": "read_file", "description": "Read a file.", "inputSchema": {"type":"object"} },
      { "name": "send_email", "description": "Send mail.", "inputSchema": {"type":"object"} }
    ]
  }
}"#;

#[test]
fn scanning_a_url_directly_enumerates_its_tools() {
    let url = spawn_mock(|_| json_200(TOOLS_RESULT));

    let output = mcpwn(&["scan", "--url", &url, "--verbose", "--no-color"]);
    let out = stdout(&output);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        out.contains("1 server(s), 2 tool(s) analysed"),
        "got:\n{out}"
    );
    // The server table and the tools themselves are rendered, exactly as they
    // would be for a server that came from a config file.
    assert!(out.contains("2 tool(s) via"), "got:\n{out}");
    assert!(out.contains("read_file"), "got:\n{out}");
    assert!(out.contains("send_email"), "got:\n{out}");
}

#[test]
fn a_url_and_a_path_together_are_rejected() {
    let tmp = TempDir::new("cli-conflict");

    let output = mcpwn(&[
        "scan",
        "--url",
        "https://example.com/mcp",
        &tmp.path().display().to_string(),
    ]);
    let err = stderr(&output);

    assert!(!output.status.success());
    assert!(
        err.contains("cannot be used with"),
        "expected an exclusivity error, got:\n{err}"
    );
    assert!(err.contains("--url"), "got:\n{err}");
}

#[test]
fn an_invalid_url_is_a_clean_error() {
    for bad in ["not-a-url", "file:///etc/passwd", "http://"] {
        let output = mcpwn(&["scan", "--url", bad]);
        let err = stderr(&output);

        assert!(!output.status.success(), "`{bad}` should fail");
        assert_eq!(output.status.code(), Some(2), "`{bad}` should exit 2");
        assert!(
            err.contains("invalid endpoint"),
            "`{bad}`: expected a clear message, got:\n{err}"
        );
        assert!(!err.contains("panicked"), "`{bad}` panicked:\n{err}");
    }
}

#[test]
fn several_urls_are_scanned_in_one_run() {
    let a = spawn_mock(|_| json_200(TOOLS_RESULT));
    let b = spawn_mock(|_| json_200(TOOLS_RESULT));

    let output = mcpwn(&["scan", "--url", &a, "--url", &b, "--no-color"]);
    let out = stdout(&output);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        out.contains("2 server(s), 4 tool(s) analysed"),
        "got:\n{out}"
    );
}

#[test]
fn an_unreachable_url_warns_but_does_not_fail_the_run() {
    let output = mcpwn(&["scan", "--url", &common::dead_url(), "--no-color"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("warning:"),
        "got:\n{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("panicked"));
}

#[test]
fn a_header_flag_authenticates_the_scan() {
    let url = spawn_mock_req(|request| {
        if !request.has_header("authorization", "Bearer s3cret") {
            return http_response(
                401,
                "Unauthorized",
                "application/json",
                r#"{"error":"nope"}"#,
            );
        }
        json_200(TOOLS_RESULT)
    });

    let without = mcpwn(&["scan", "--url", &url, "--no-color"]);
    assert!(
        stderr(&without).contains("HTTP 401"),
        "{}",
        stderr(&without)
    );

    let with = mcpwn(&[
        "scan",
        "--url",
        &url,
        "--header",
        "Authorization: Bearer s3cret",
        "--no-color",
    ]);
    let out = stdout(&with);
    assert!(with.status.success(), "stderr: {}", stderr(&with));
    assert!(
        out.contains("1 server(s), 2 tool(s) analysed"),
        "got:\n{out}"
    );
    assert!(
        stderr(&with).is_empty(),
        "unexpected warnings: {}",
        stderr(&with)
    );
}

#[test]
fn several_header_flags_are_accepted() {
    let url = spawn_mock_req(|request| {
        if request.has_header("x-a", "1") && request.has_header("x-b", "2") {
            json_200(TOOLS_RESULT)
        } else {
            http_response(400, "Bad Request", "text/plain", "missing headers")
        }
    });

    let output = mcpwn(&[
        "scan",
        "--url",
        &url,
        "-H",
        "X-A: 1",
        "-H",
        "X-B: 2",
        "--no-color",
    ]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("2 tool(s) analysed"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_malformed_header_is_a_clean_error_that_hides_the_value() {
    let output = mcpwn(&[
        "scan",
        "--url",
        "https://example.com/mcp",
        "-H",
        "Authorization sup3rs3cret",
    ]);
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(2));
    assert!(err.contains("invalid header"), "got:\n{err}");
    assert!(!err.contains("panicked"), "got:\n{err}");
    // A bad header must not print the secret it contained.
    assert!(!err.contains("sup3rs3cret"), "the value leaked:\n{err}");
}

#[test]
fn scanning_a_project_path_still_works() {
    let tmp = TempDir::new("cli-path");
    tmp.write(
        ".cursor/mcp.json",
        r#"{"mcpServers":{"local":{"command":"npx","args":["-y","x"]}}}"#,
    );

    let output = mcpwn(&["scan", &tmp.path().display().to_string(), "--no-color"]);
    let out = stdout(&output);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(out.contains("1 server(s)"), "got:\n{out}");
    assert!(out.contains("stdio server"), "got:\n{out}");
}
