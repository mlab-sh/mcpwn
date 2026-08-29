//! `mcpwn audit`: the command that launches processes and calls tools.
//!
//! The tests that matter most here are the negative ones. This is the only part
//! of the project that acts on a target, so what it refuses to do is as much
//! the specification as what it does.

#![cfg(unix)]

mod common;

use std::process::{Command, Output};

use common::TempDir;

use mcpwn::audit::probes::build_arguments;
use mcpwn::engagement::Engagement;
use serde_json::json;

fn audit(args: &[&str]) -> Output {
    let mut full = vec!["audit"];
    full.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_mcpwn"))
        .args(&full)
        .output()
        .expect("run the mcpwn binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A deliberately vulnerable MCP server over stdio, written to a temp dir.
///
/// Local, short-lived, and reachable by nothing but this test.
const VULNERABLE_SERVER: &str = r#"#!/usr/bin/env python3
import json, sys, subprocess

TOOLS = [
 {"name":"read_file","description":"Reads a file.",
  "inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},
 {"name":"fetch_url","description":"Fetches a URL.",
  "inputSchema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}},
 {"name":"search_db","description":"Searches.",
  "inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}},
 {"name":"run_task","description":"Runs a task.",
  "inputSchema":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}},
 {"name":"safe_greet","description":"Greets.",
  "inputSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}},
]

def call(name, args):
    if name == "read_file":
        try: return open(args.get("path","")).read()[:2000]
        except Exception as e: return "error: %s" % e
    if name == "fetch_url":
        u = args.get("url","")
        if "169.254.169.254" in u: return "ami-id\nreservation-id\n"
        return "fetched " + u
    if name == "search_db":
        q = args.get("query","")
        if q.count("'") % 2 == 1: return 'error: unterminated quoted string at or near "\'"'
        return "0 results"
    if name == "run_task":
        return subprocess.run("echo task: " + args.get("command",""), shell=True,
                              capture_output=True, text=True).stdout[:2000]
    return "hello"

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: msg = json.loads(line)
    except Exception: continue
    m, mid = msg.get("method"), msg.get("id")
    if mid is None: continue
    if m == "initialize":
        out = {"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}
    elif m == "tools/list":
        out = {"jsonrpc":"2.0","id":mid,"result":{"tools":TOOLS}}
    elif m == "tools/call":
        p = msg.get("params",{})
        out = {"jsonrpc":"2.0","id":mid,"result":{"content":[
            {"type":"text","text":call(p.get("name"), p.get("arguments",{}))}]}}
    else:
        out = {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"no"}}
    print(json.dumps(out), flush=True)
"#;

/// Write the server and an engagement pointing at it.
fn engagement_for(tmp: &TempDir, tools: &str, extra: &str) -> String {
    let server = tmp.write("server.py", VULNERABLE_SERVER);
    let engagement = tmp.write(
        "engagement.toml",
        &format!(
            r#"target = "stdio:python3"
args = ["{}"]
authorized_by = "tests@example.com"
reference = "SELF-TEST"

[limits]
rate_per_second = 50
max_requests = 200
timeout_seconds = 15

[tools]
allow = {tools}
{extra}
"#,
            server.display()
        ),
    );
    engagement.display().to_string()
}

// --- what it finds ----------------------------------------------------------

#[test]
fn the_three_ungated_probes_find_their_defects() {
    let tmp = TempDir::new("audit-hits");
    let path = engagement_for(&tmp, r#"["read_file", "fetch_url", "search_db"]"#, "");

    let output = audit(&[
        "run",
        "-e",
        &path,
        "--transcript",
        &tmp.path().join("t.jsonl").display().to_string(),
        "--no-color",
    ]);
    let out = stdout(&output);

    assert!(out.contains("MCPWN-ACT-001"), "path traversal:\n{out}");
    assert!(out.contains("MCPWN-ACT-003"), "sql injection:\n{out}");
    assert!(out.contains("MCPWN-ACT-004"), "ssrf:\n{out}");
    assert_eq!(output.status.code(), Some(1), "findings mean exit 1");
}

#[test]
fn a_tool_with_no_matching_parameter_is_left_alone() {
    let tmp = TempDir::new("audit-benign");
    let path = engagement_for(&tmp, r#"["safe_greet"]"#, "");

    let output = audit(&[
        "run",
        "-e",
        &path,
        "--transcript",
        &tmp.path().join("t.jsonl").display().to_string(),
        "--no-color",
    ]);

    assert!(
        stdout(&output).contains("no findings"),
        "{}",
        stdout(&output)
    );
    assert_eq!(output.status.code(), Some(0));
    // Nothing was sent: no probe applies to a `name` parameter.
    assert!(
        stderr(&output).contains("0 call(s) sent"),
        "{}",
        stderr(&output)
    );
}

// --- what it refuses --------------------------------------------------------

#[test]
fn a_tool_that_takes_a_command_line_is_not_probed_by_default() {
    let tmp = TempDir::new("audit-gate");
    let path = engagement_for(&tmp, r#"["run_task"]"#, "");

    let output = audit(&[
        "run",
        "-e",
        &path,
        "--transcript",
        &tmp.path().join("t.jsonl").display().to_string(),
        "--no-color",
    ]);

    assert!(
        stderr(&output).contains("skipping `run_task`"),
        "probing it would run it:\n{}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("MCPWN-ACT-002"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_gate_opens_only_when_the_engagement_says_so() {
    let tmp = TempDir::new("audit-gate-open");
    let path = engagement_for(&tmp, r#"["run_task"]"#, "allow_dangerous = true");

    let output = audit(&[
        "run",
        "-e",
        &path,
        "--transcript",
        &tmp.path().join("t.jsonl").display().to_string(),
        "--no-color",
    ]);

    assert!(
        stdout(&output).contains("MCPWN-ACT-002"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_tool_outside_the_engagement_is_never_touched() {
    let tmp = TempDir::new("audit-scope");
    // The server is vulnerable in three ways; only one tool is in scope.
    let path = engagement_for(&tmp, r#"["search_db"]"#, "");
    let transcript = tmp.path().join("t.jsonl");

    let output = audit(&[
        "run",
        "-e",
        &path,
        "--transcript",
        &transcript.display().to_string(),
        "--no-color",
    ]);
    let out = stdout(&output);

    assert!(out.contains("MCPWN-ACT-003"), "{out}");
    assert!(
        !out.contains("MCPWN-ACT-001"),
        "read_file is out of scope:\n{out}"
    );
    assert!(
        !out.contains("MCPWN-ACT-004"),
        "fetch_url is out of scope:\n{out}"
    );

    // The scope is enforced at the wire, not just in the report.
    let log = std::fs::read_to_string(&transcript).expect("transcript");
    assert!(
        !log.contains("read_file"),
        "a tool outside scope was called"
    );
    assert!(
        !log.contains("fetch_url"),
        "a tool outside scope was called"
    );
}

#[test]
fn a_dry_run_sends_nothing() {
    let tmp = TempDir::new("audit-dry");
    let path = engagement_for(&tmp, r#"["read_file", "fetch_url"]"#, "");
    let transcript = tmp.path().join("t.jsonl");

    let output = audit(&[
        "run",
        "-e",
        &path,
        "--dry-run",
        "--transcript",
        &transcript.display().to_string(),
        "--no-color",
    ]);

    assert!(
        stdout(&output).contains("nothing is sent"),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("path-traversal"),
        "{}",
        stdout(&output)
    );
    assert!(
        !transcript.exists(),
        "a dry run must not even open a transcript"
    );
}

// --- the engagement file is the gate ----------------------------------------

#[test]
fn an_engagement_with_no_tools_is_refused() {
    let tmp = TempDir::new("audit-empty");
    let path = tmp.write(
        "engagement.toml",
        "target = \"https://x.test/mcp\"\nauthorized_by = \"a@b\"\n\n[tools]\nallow = []\n",
    );

    let err = Engagement::load(&path).expect_err("refused").to_string();
    assert!(err.contains("nothing would be called"), "{err}");
}

#[test]
fn an_engagement_with_no_authorisation_is_refused() {
    let tmp = TempDir::new("audit-unsigned");
    let path = tmp.write(
        "engagement.toml",
        "target = \"https://x.test/mcp\"\nauthorized_by = \"\"\n\n[tools]\nallow = [\"x\"]\n",
    );

    let err = Engagement::load(&path).expect_err("refused").to_string();
    assert!(err.contains("authorized_by"), "{err}");
}

#[test]
fn an_absurd_rate_or_ceiling_is_refused() {
    let tmp = TempDir::new("audit-limits");
    for (limits, expected) in [
        ("rate_per_second = 500", "rate_per_second"),
        ("max_requests = 0", "max_requests"),
    ] {
        let path = tmp.write(
            &format!("e{}.toml", expected.len()),
            &format!(
                "target = \"https://x.test/mcp\"\nauthorized_by = \"a@b\"\n\n[limits]\n{limits}\n\n[tools]\nallow = [\"x\"]\n"
            ),
        );
        let err = Engagement::load(&path).expect_err("refused").to_string();
        assert!(err.contains(expected), "{err}");
    }
}

#[test]
fn the_template_is_a_valid_engagement_once_filled_in() {
    let tmp = TempDir::new("audit-template");
    let printed = stdout(&audit(&["init"]));
    let path = tmp.write("engagement.toml", &printed);

    // The template ships with a placeholder target and a real tool list, so it
    // loads: what it does not do is point anywhere real.
    let engagement = Engagement::load(&path).expect("the template must load");
    assert_eq!(engagement.target, "https://mcp.example.com/mcp");
    assert!(!engagement.tools.allow_dangerous);
    assert_eq!(engagement.limits.rate_per_second, 2.0);
}

#[test]
fn there_is_no_way_to_name_a_target_on_the_command_line() {
    // The engagement file is the only way in. A `--url` would make it possible
    // to point this at something by reflex, which is exactly what the file is
    // there to prevent.
    let output = audit(&["run", "--url", "https://example.com/mcp"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("unexpected argument"),
        "{}",
        stderr(&output)
    );
}

// --- argument construction --------------------------------------------------

#[test]
fn the_payload_lands_at_the_right_place_in_a_nested_schema() {
    let schema = json!({
        "type": "object",
        "properties": {
            "requests": { "type": "array", "items": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "max_length": { "type": "integer" }
                },
                "required": ["url", "max_length"]
            }},
            "mode": { "type": "string", "enum": ["fast", "slow"] }
        },
        "required": ["requests", "mode"]
    });

    let arguments = build_arguments(&schema, "requests[].url", "PAYLOAD");

    assert_eq!(arguments["requests"][0]["url"], "PAYLOAD");
    // Other required fields are filled so the call is not rejected for a
    // missing argument, which would say nothing about the one being probed.
    assert_eq!(arguments["requests"][0]["max_length"], 1);
    assert_eq!(
        arguments["mode"], "fast",
        "an enum is filled from its own values"
    );
}

#[test]
fn optional_parameters_are_left_out() {
    let schema = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "recursive": { "type": "boolean" }
        },
        "required": ["path"]
    });

    let arguments = build_arguments(&schema, "path", "PAYLOAD");
    assert_eq!(arguments["path"], "PAYLOAD");
    assert!(arguments.get("recursive").is_none(), "{arguments}");
}
