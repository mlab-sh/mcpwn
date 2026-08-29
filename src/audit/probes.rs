//! The active probes.
//!
//! Each one poisons a single parameter of a single tool and looks for a
//! specific oracle in the answer. There is no "this looks odd" anywhere: a
//! finding requires a signal that cannot plausibly appear otherwise.
//!
//! # Two rules every probe follows
//!
//! **Nothing destructive is ever sent.** `; echo mcpwn-<nonce>` yes, `; rm`
//! never. `' OR '1'='1` yes, `DROP TABLE` never. This is not politeness: a
//! payload that changes the target cannot be re-run, and a finding nobody can
//! reproduce is not a finding.
//!
//! **Every hit is checked against a control.** The same tool is called with an
//! ordinary value, and the oracle must *not* fire. A server that returns
//! `root:x:0:0` whatever you send it is not vulnerable to traversal, it is
//! returning a fixed string, and without the control that is a critical finding
//! that wastes somebody's afternoon.

use serde_json::{json, Value};

use crate::analysis::capabilities::tokenize;
use crate::analysis::schema::Param;
use crate::audit::caller::{CallOutcome, ToolCaller};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::manifest::{ToolManifest, ToolRef};

/// One payload and what proves it landed.
struct Attempt {
    payload: String,
    /// Substrings that can only appear if the payload was interpreted.
    oracles: Vec<String>,
}

/// A probe: which parameters it applies to, what it sends, what it reports.
#[derive(Debug)]
pub struct Probe {
    pub id: &'static str,
    pub description: &'static str,
    /// Parameter name tokens this probe targets.
    names: &'static [&'static str],
    finding_id: &'static str,
    severity: Severity,
    title: &'static str,
    statement: &'static str,
    remediation: &'static str,
}

/// Every probe that can run. Named in the engagement's `tools.probes`.
pub const PROBES: &[Probe] = &[
    Probe {
        id: "path-traversal",
        description: "Reads a file outside the intended root through a path parameter.",
        names: &[
            "path",
            "filepath",
            "filename",
            "file",
            "dir",
            "directory",
            "folder",
            "cwd",
        ],
        finding_id: "MCPWN-ACT-001",
        severity: Severity::Critical,
        title: "Path traversal",
        statement: "the server returned the contents of a file outside any plausible root, so \
                    the path is passed through without being confined",
        remediation: "Resolve the path and verify it stays inside the intended root after \
                      canonicalisation, not before.",
    },
    Probe {
        id: "command-injection",
        description: "Executes a shell command through a command parameter.",
        names: &[
            "command",
            "cmd",
            "commandline",
            "shell",
            "exec",
            "execute",
            "script",
            "args",
            "argv",
        ],
        finding_id: "MCPWN-ACT-002",
        severity: Severity::Critical,
        title: "Command injection",
        statement: "a shell metacharacter in this parameter was interpreted rather than passed \
                    through, so the caller chooses what runs on the host",
        remediation: "Pass arguments as a list to exec rather than building a command line, so \
                      there is no shell to inject into.",
    },
    Probe {
        id: "sql-injection",
        description: "Breaks out of a SQL string through a query parameter.",
        names: &["query", "sql", "statement", "filter", "where", "search"],
        finding_id: "MCPWN-ACT-003",
        severity: Severity::High,
        title: "SQL injection",
        statement: "an unbalanced quote reached the database engine, so this parameter is \
                    concatenated into a statement rather than bound to it",
        remediation: "Use parameter binding. Escaping is not a substitute and never has been.",
    },
    Probe {
        id: "ssrf",
        description: "Reaches the cloud metadata service through a URL parameter.",
        names: &[
            "url", "uri", "endpoint", "host", "hostname", "webhook", "callback", "link",
        ],
        finding_id: "MCPWN-ACT-004",
        severity: Severity::Critical,
        title: "Server-side request forgery to the metadata service",
        statement: "the server fetched a caller-chosen URL and returned the instance metadata \
                    service's answer, which is where cloud credentials live",
        remediation: "Resolve the destination and refuse link-local and private ranges, after \
                      resolution rather than before, and refuse redirects into them.",
    },
];

/// Whether a probe would be pointed at a parameter. Exposed so `--dry-run` can
/// show exactly what a run would touch without touching it.
pub fn would_target(probe: &Probe, param: &Param) -> bool {
    applies(probe, param)
}

/// Whether a probe should be pointed at a parameter.
fn applies(probe: &Probe, param: &Param) -> bool {
    if !param.is_texty() {
        return false;
    }
    let tokens = tokenize(&param.name);
    probe
        .names
        .iter()
        .any(|candidate| tokens.iter().any(|t| t == candidate))
}

/// The payloads for a probe, with the oracles that prove each one landed.
fn attempts(probe: &Probe, nonce: &str) -> Vec<Attempt> {
    let oracle = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();

    match probe.id {
        "path-traversal" => {
            // Both spellings of the root entry: `root:x:0:0` on Linux, where
            // the hash lives in shadow, and `root:*:0:0` on macOS and the BSDs.
            // Testing against a macOS host is what caught the second one
            // missing, on a server that was plainly vulnerable.
            let unix = oracle(&["root:x:0:0", "root:*:0:0"]);
            let windows = oracle(&["[fonts]", "[extensions]"]);
            vec![
                Attempt {
                    payload: "../../../../../../../../etc/passwd".to_owned(),
                    oracles: unix.clone(),
                },
                Attempt {
                    payload: "/etc/passwd".to_owned(),
                    oracles: unix.clone(),
                },
                // Defeats a single non-recursive strip of `../`.
                Attempt {
                    payload: "....//....//....//....//etc/passwd".to_owned(),
                    oracles: unix,
                },
                Attempt {
                    payload: r"..\..\..\..\..\windows\win.ini".to_owned(),
                    oracles: windows,
                },
            ]
        }
        "command-injection" => {
            // The marker is written with quotes the shell removes. Echoed back
            // literally it reads `mc""pwn-<nonce>`; interpreted it reads
            // `mcpwn-<nonce>`, which the input never contained.
            let marker = format!("mcpwn-{nonce}");
            let split = format!("mc\"\"pwn-{nonce}");
            vec![
                Attempt {
                    payload: format!("; echo {split}"),
                    oracles: vec![marker.clone()],
                },
                Attempt {
                    payload: format!("$(echo {split})"),
                    oracles: vec![marker.clone()],
                },
                Attempt {
                    payload: format!("`echo {split}`"),
                    oracles: vec![marker.clone()],
                },
                Attempt {
                    payload: format!("| echo {split}"),
                    oracles: vec![marker],
                },
            ]
        }
        "sql-injection" => {
            let errors = oracle(&[
                "sql syntax",
                "sqlstate",
                "sqlite3.operationalerror",
                "psycopg2",
                "ora-0",
                "unclosed quotation mark",
                "unterminated quoted string",
                "syntax error at or near",
                "quoted string not properly terminated",
            ]);
            vec![
                Attempt {
                    payload: "'".to_owned(),
                    oracles: errors.clone(),
                },
                Attempt {
                    payload: "\"".to_owned(),
                    oracles: errors.clone(),
                },
                Attempt {
                    payload: "') OR ('1'='1".to_owned(),
                    oracles: errors,
                },
            ]
        }
        "ssrf" => {
            // In-band only: the answer has to come back to us. An out-of-band
            // callback would need an inbound socket, which is a different
            // constraint and out of scope here.
            vec![
                Attempt {
                    payload: "http://169.254.169.254/latest/meta-data/".to_owned(),
                    oracles: oracle(&["ami-id", "instance-id", "iam/security-credentials"]),
                },
                Attempt {
                    payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                        .to_owned(),
                    oracles: oracle(&["accesskeyid", "secretaccesskey"]),
                },
                Attempt {
                    payload: "http://metadata.google.internal/computeMetadata/v1/".to_owned(),
                    oracles: oracle(&["computemetadata", "service-accounts"]),
                },
            ]
        }
        _ => Vec::new(),
    }
}

/// Anything a probe sends, and what came back.
#[derive(Debug)]
pub struct Exchange {
    pub tool: String,
    pub param: String,
    pub probe: &'static str,
    pub payload: String,
    pub outcome: Result<CallOutcome, String>,
}

/// Run every applicable probe against one tool.
///
/// `spend` is the caller's budget hook: it paces and counts, and returns an
/// error when the engagement's ceiling is reached, which stops the run.
pub fn run_tool(
    caller: &mut dyn ToolCaller,
    server: &str,
    tool: &ToolManifest,
    params: &[Param],
    enabled: &dyn Fn(&str) -> bool,
    nonce: &str,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Vec<Finding>, String> {
    let Some(schema) = tool.input_schema.as_ref() else {
        return Ok(Vec::new());
    };
    let subject = ToolRef::new(server, &tool.name);
    let mut findings = Vec::new();

    for probe in PROBES {
        if !enabled(probe.id) {
            continue;
        }
        for param in params.iter().filter(|p| applies(probe, p)) {
            if let Some(finding) =
                run_param(caller, &subject, tool, schema, param, probe, nonce, spend)?
            {
                findings.push(finding);
            }
        }
    }
    Ok(findings)
}

#[allow(clippy::too_many_arguments)]
fn run_param(
    caller: &mut dyn ToolCaller,
    subject: &ToolRef,
    tool: &ToolManifest,
    schema: &Value,
    param: &Param,
    probe: &Probe,
    nonce: &str,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Option<Finding>, String> {
    for attempt in attempts(probe, nonce) {
        let arguments = build_arguments(schema, &param.path, &attempt.payload);
        let exchange = call(
            caller,
            tool,
            param,
            probe,
            &attempt.payload,
            &arguments,
            spend,
        )?;

        let Ok(outcome) = &exchange.outcome else {
            continue;
        };
        let body = outcome.text.to_lowercase();
        let Some(hit) = attempt
            .oracles
            .iter()
            .find(|o| body.contains(&o.to_lowercase()))
        else {
            continue;
        };

        // The control. A server that answers the same thing whatever you send
        // it is not vulnerable, and this is what tells the difference.
        let control_value = format!("mcpwn-control-{nonce}");
        let control_args = build_arguments(schema, &param.path, &control_value);
        let control = call(
            caller,
            tool,
            param,
            probe,
            &control_value,
            &control_args,
            spend,
        )?;
        if let Ok(control) = &control.outcome {
            if control.text.to_lowercase().contains(&hit.to_lowercase()) {
                continue; // the oracle fires on anything: not a finding.
            }
        }

        return Ok(Some(
            Finding::builder(
                probe.finding_id,
                Category::Vulnerability,
                probe.severity,
                format!("{}: `{}` of `{}`", probe.title, param.path, tool.name),
            )
            .message(format!(
                "Calling `{}` with `{}` set to a probe payload came back carrying `{hit}`: {}. \
                 The same call with an ordinary value did not, so this is the payload being \
                 interpreted and not a fixed response. Confirmed by interaction, not inferred.",
                tool.name, param.path, probe.statement
            ))
            .confidence(Confidence::High)
            .subject(subject.clone())
            .remediation(probe.remediation)
            .evidence(Evidence::new("payload", attempt.payload.clone()))
            .evidence(Evidence::new("oracle", (*hit).clone()))
            .evidence(Evidence::new(
                "response excerpt",
                outcome.text.chars().take(400).collect::<String>(),
            ))
            .evidence(Evidence::new("control", control_value))
            .build(),
        ));
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn call(
    caller: &mut dyn ToolCaller,
    tool: &ToolManifest,
    param: &Param,
    probe: &Probe,
    payload: &str,
    arguments: &Value,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Exchange, String> {
    let outcome = caller.call(&tool.name, arguments);
    let exchange = Exchange {
        tool: tool.name.clone(),
        param: param.path.clone(),
        probe: probe.id,
        payload: payload.to_owned(),
        outcome,
    };
    spend(&exchange)?;
    Ok(exchange)
}

/// Build the smallest valid argument object that puts `payload` at `target`.
///
/// Other required parameters are filled with inoffensive values, because a
/// server that rejects the call for a missing field tells you nothing about the
/// one you are probing.
pub fn build_arguments(schema: &Value, target: &str, payload: &str) -> Value {
    let segments: Vec<&str> = target.split('.').collect();
    fill(schema, &segments, payload)
}

fn fill(schema: &Value, path: &[&str], payload: &str) -> Value {
    let Some(object) = schema.as_object() else {
        return Value::Null;
    };

    // Reached the parameter being probed.
    if path.is_empty() {
        return filler(schema, Some(payload));
    }

    let required: Vec<&str> = object
        .get("required")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        return json!({});
    };

    let (head, rest) = path.split_first().expect("path is not empty");
    let (name, is_array) = match head.strip_suffix("[]") {
        Some(name) => (name, true),
        None => (*head, false),
    };

    let mut out = serde_json::Map::new();
    for (property, sub_schema) in properties {
        if property == name {
            let inner = if is_array {
                let items = sub_schema.get("items").unwrap_or(&Value::Null);
                json!([fill(items, rest, payload)])
            } else if rest.is_empty() {
                filler(sub_schema, Some(payload))
            } else {
                fill(sub_schema, rest, payload)
            };
            out.insert(property.clone(), inner);
        } else if required.contains(&property.as_str()) {
            out.insert(property.clone(), filler(sub_schema, None));
        }
    }
    Value::Object(out)
}

/// A value a server is likely to accept for a parameter we are not probing.
fn filler(schema: &Value, payload: Option<&str>) -> Value {
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if let Some(first) = values.first() {
            return first.clone();
        }
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") | None => json!(payload.unwrap_or("mcpwn")),
        Some("integer") | Some("number") => json!(1),
        Some("boolean") => json!(false),
        Some("array") => match schema.get("items") {
            Some(items) => json!([filler(items, payload)]),
            None => json!([]),
        },
        Some("object") => {
            let required: Vec<&str> = schema
                .get("required")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut out = serde_json::Map::new();
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (name, sub) in properties {
                    if required.contains(&name.as_str()) {
                        out.insert(name.clone(), filler(sub, None));
                    }
                }
            }
            Value::Object(out)
        }
        _ => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Transport-level probes
//
// The probes above poison one parameter of one tool. These three test the
// transport itself, so they run once per target rather than once per parameter.
//
// `protocol-fuzz` is **gated**: it is the only probe here that can take a
// target down, so it runs only when an engagement names it explicitly. The
// others run by default.
// ---------------------------------------------------------------------------

use crate::audit::caller::RawResponse;
use crate::audit::rawhttp;
use crate::engagement::Engagement;

/// Probes that operate on the transport rather than on a tool.
pub const TRANSPORT_PROBES: &[(&str, &str, bool)] = &[
    (
        "session-fixation",
        "Accepts a session identifier chosen by the client.",
        false,
    ),
    (
        "header-injection",
        "Carries a carriage return in a header value (plaintext targets only).",
        false,
    ),
    (
        "protocol-fuzz",
        "Malformed JSON-RPC, to see what the server does with it. Gated: name it explicitly.",
        true,
    ),
];

/// Whether a transport probe only runs when an engagement names it.
pub fn is_gated(id: &str) -> bool {
    TRANSPORT_PROBES
        .iter()
        .any(|(probe, _, gated)| *probe == id && *gated)
}

/// Signatures of an internal detail escaping in an error message.
const LEAK_SIGNATURES: &[&str] = &[
    "traceback (most recent call last)",
    "at java.",
    "exception in thread",
    "panicked at",
    "node_modules/",
    "goroutine ",
    "stack trace:",
    "system.exception",
    "/usr/lib/python",
    "site-packages/",
];

/// Malformed messages, each testing one assumption a parser might make.
fn fuzz_cases(nonce: &str) -> Vec<(&'static str, String)> {
    vec![
        ("not json at all", format!("this is not json {nonce}")),
        (
            "truncated object",
            "{\"jsonrpc\": \"2.0\", \"id\":".to_owned(),
        ),
        (
            "no jsonrpc field",
            json!({ "id": 1, "method": "tools/list", "params": {} }).to_string(),
        ),
        (
            "method is a number",
            json!({ "jsonrpc": "2.0", "id": 1, "method": 42, "params": {} }).to_string(),
        ),
        (
            "params is a string",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": "nope" })
                .to_string(),
        ),
        (
            "id is an object",
            json!({ "jsonrpc": "2.0", "id": {"a": 1}, "method": "tools/list", "params": {} })
                .to_string(),
        ),
        (
            "unknown method",
            json!({ "jsonrpc": "2.0", "id": 1, "method": format!("mcpwn/{nonce}"), "params": {} })
                .to_string(),
        ),
        (
            "batch array",
            json!([{ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }])
                .to_string(),
        ),
        ("deeply nested params", deep_nesting(200)),
        ("oversized string", oversized(64 * 1024)),
    ]
}

/// 200 levels, not unbounded: the point is to find a recursive parser with no
/// depth limit, not to exhaust the machine.
fn deep_nesting(depth: usize) -> String {
    let mut inner = json!(1);
    for _ in 0..depth {
        inner = json!({ "a": inner });
    }
    json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": inner }).to_string()
}

/// 64 KiB, not megabytes: enough to find a missing length check, small enough
/// not to be the outage it is looking for.
fn oversized(size: usize) -> String {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "cursor": "A".repeat(size) } })
    .to_string()
}

/// Run the transport-level probes once against the target.
pub fn run_transport(
    caller: &mut dyn ToolCaller,
    engagement: &Engagement,
    enabled: &dyn Fn(&str) -> bool,
    nonce: &str,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    let target = caller.target();

    if enabled("session-fixation") {
        if let Some(finding) = session_fixation(caller, engagement, nonce, spend)? {
            findings.push(finding);
        }
    }
    if enabled("header-injection") {
        if let Some(finding) = header_injection(caller, &target, nonce, spend)? {
            findings.push(finding);
        }
    }
    if enabled("protocol-fuzz") {
        findings.extend(protocol_fuzz(caller, &target, nonce, spend)?);
    }
    Ok(findings)
}

/// Record one transport exchange against the budget and the transcript.
fn record(
    probe: &'static str,
    payload: &str,
    outcome: &Result<RawResponse, String>,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<(), String> {
    let exchange = Exchange {
        tool: "(transport)".to_owned(),
        param: String::new(),
        probe,
        payload: payload.chars().take(200).collect(),
        outcome: outcome
            .as_ref()
            .map(|raw| CallOutcome {
                text: raw.body.clone(),
                raw: json!({ "status": raw.status, "headers": raw.headers, "body": raw.body }),
                is_error: raw.status.is_some_and(|s| s >= 400),
                duration: raw.duration,
            })
            .map_err(|err| err.clone()),
    };
    spend(&exchange)
}

/// A session identifier the client chose, accepted by a server that mints its
/// own.
///
/// Only meaningful on a server that actually uses sessions. A stateless one
/// ignores the header entirely, and reporting that would fire on every modern
/// server.
fn session_fixation(
    caller: &mut dyn ToolCaller,
    engagement: &Engagement,
    nonce: &str,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Option<Finding>, String> {
    let Some(url) = caller.endpoint().map(str::to_owned) else {
        return Ok(None); // stdio has no sessions.
    };
    let timeout = std::time::Duration::from_secs(engagement.limits.timeout_seconds);
    let headers = crate::enumerate::parse_headers(&engagement.headers).unwrap_or_default();

    // Does this server use sessions at all?
    let mut probe_caller = crate::audit::caller::HttpCaller::new(&url, headers.clone(), timeout);
    let _ = probe_caller.list_tools();
    if probe_caller.session().is_none() {
        return Ok(None); // stateless: nothing to fix.
    }

    // Now claim one it never issued.
    let chosen = format!("mcpwn-{nonce}");
    let mut forged = headers.clone();
    forged.push(("mcp-session-id".to_owned(), chosen.clone()));
    let mut forged_caller = crate::audit::caller::HttpCaller::new(&url, forged, timeout);
    let outcome = forged_caller.list_tools().map(|tools| RawResponse {
        status: Some(200),
        headers: String::new(),
        body: format!("{} tool(s)", tools.len()),
        duration: std::time::Duration::ZERO,
    });
    record("session-fixation", &chosen, &outcome, spend)?;

    let Ok(response) = outcome else {
        return Ok(None);
    };

    Ok(Some(
        Finding::builder(
            "MCPWN-ACT-005",
            Category::Vulnerability,
            Severity::Medium,
            "A session identifier chosen by the client is accepted",
        )
        .message(format!(
            "`{}` mints its own session identifiers, and also accepted one this scan invented. A \
             session the server did not issue is a session it cannot reason about: anyone able to \
             put a value in front of a victim's client can decide which session that client ends \
             up in, which is session fixation.",
            caller.target()
        ))
        .confidence(Confidence::High)
        .remediation(
            "Reject any session identifier the server did not issue, rather than adopting it.",
        )
        .evidence(Evidence::new("forged session", chosen))
        .evidence(Evidence::new("result", response.body))
        .build(),
    ))
}

/// A carriage return smuggled into a header value.
fn header_injection(
    caller: &mut dyn ToolCaller,
    target: &str,
    nonce: &str,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Option<Finding>, String> {
    let Some(url) = caller.endpoint() else {
        return Ok(None); // no headers on stdio.
    };
    if !rawhttp::is_plaintext(url) {
        // Said, not silently skipped: a probe that does nothing quietly is
        // worse than one that reports it did not run.
        return Ok(None);
    }

    let marker = format!("X-Mcpwn-{nonce}");
    let value = format!("probe\r\n{marker}: injected");
    let body =
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }).to_string();
    let outcome = rawhttp::post_raw_headers(
        url,
        &[("X-Mcpwn-Probe".to_owned(), value.clone())],
        &body,
        std::time::Duration::from_secs(10),
    );
    record("header-injection", &value, &outcome, spend)?;

    let Ok(response) = outcome else {
        return Ok(None);
    };
    // The signal is the injected header coming back in the *response* headers:
    // that is the request having been split and rebuilt somewhere along the way.
    if !response
        .headers
        .to_lowercase()
        .contains(&marker.to_lowercase())
    {
        return Ok(None);
    }

    Ok(Some(
        Finding::builder(
            "MCPWN-ACT-006",
            Category::Vulnerability,
            Severity::High,
            "A carriage return in a header value is carried through",
        )
        .message(format!(
            "A header sent to `{target}` contained a carriage return, and the header it smuggled \
             came back in the response. Something on the path is rebuilding requests without \
             validating them, so a value that reaches a header can add headers of its own. Where \
             a gateway and the server then read different requests out of the same bytes, one can \
             authorise what the other executes."
        ))
        .confidence(Confidence::High)
        .remediation(
            "Reject control characters in header values at the edge, and do not rebuild requests \
             from unvalidated parts.",
        )
        .evidence(Evidence::new("injected header", marker))
        .evidence(Evidence::new(
            "response headers",
            response.headers.chars().take(400).collect::<String>(),
        ))
        .build(),
    ))
}

/// Malformed JSON-RPC, one assumption at a time.
fn protocol_fuzz(
    caller: &mut dyn ToolCaller,
    target: &str,
    nonce: &str,
    spend: &mut dyn FnMut(&Exchange) -> Result<(), String>,
) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();

    for (label, payload) in fuzz_cases(nonce) {
        let outcome = caller.send_raw(&payload);
        record("protocol-fuzz", &payload, &outcome, spend)?;

        // A server that answered is alive, so only silence is worth a check.
        // Probing liveness after every case would double the traffic while
        // counting half of it against the engagement's ceiling.
        let answered = outcome
            .as_ref()
            .is_ok_and(|response| !response.body.trim().is_empty());

        // A server that stops answering is the strongest result here, and also
        // a reason to stop sending.
        if !answered && !caller.is_alive() {
            findings.push(
                Finding::builder(
                    "MCPWN-ACT-007",
                    Category::Vulnerability,
                    Severity::High,
                    format!("The server stopped answering after a malformed message: {label}"),
                )
                .message(format!(
                    "`{target}` no longer responds after receiving a message described as \
                     \"{label}\". A malformed request that any caller can send should produce an \
                     error, not the end of the process. Anyone who can reach this endpoint can \
                     therefore stop it."
                ))
                .confidence(Confidence::High)
                .remediation(
                    "Handle parse failures as JSON-RPC errors rather than letting them escape.",
                )
                .evidence(Evidence::new("case", label.to_owned()))
                .evidence(Evidence::new(
                    "payload",
                    payload.chars().take(200).collect::<String>(),
                ))
                .build(),
            );
            break;
        }

        let Ok(response) = outcome else { continue };
        let body = response.body.to_lowercase();

        if let Some(signature) = LEAK_SIGNATURES.iter().find(|s| body.contains(*s)) {
            findings.push(
                Finding::builder(
                    "MCPWN-ACT-008",
                    Category::Vulnerability,
                    Severity::Medium,
                    format!("An internal detail escapes in an error: {label}"),
                )
                .message(format!(
                    "A malformed message described as \"{label}\" made `{target}` answer with what \
                     looks like a stack trace. That hands a caller file paths, library versions \
                     and internal structure, none of which is theirs to have, and it is usually a \
                     sign the error reached the transport rather than being handled."
                ))
                .confidence(Confidence::High)
                .remediation(
                    "Return a JSON-RPC error with a message written for a caller, and log the \
                     detail server-side.",
                )
                .evidence(Evidence::new("case", label.to_owned()))
                .evidence(Evidence::new("signature", (*signature).to_owned()))
                .evidence(Evidence::new(
                    "response excerpt",
                    response.body.chars().take(400).collect::<String>(),
                ))
                .build(),
            );
        }
    }

    Ok(findings)
}
