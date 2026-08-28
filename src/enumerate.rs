//! Step 3: fill in a server's tools, **statically only**.
//!
//! # The safety rule
//!
//! mcpwn never spawns a server process. A stdio server's tool list is only
//! obtainable by executing the very binary we are trying to audit, so stdio
//! servers are reported [`Enumeration::NotPossible`] and left alone. That is a
//! normal outcome, not an error. [`tests/enumerate.rs`] nails this down with a
//! config whose command would create a witness file if it were ever run.
//!
//! A remote HTTP server is different: asking its endpoint for `tools/list` is a
//! read-only network request, not local code execution, so it *is* enumerable
//! here.
//!
//! # Protocol
//!
//! Checked against the specification on 2026-08-28. The current revision is
//! **2026-07-28**, which made MCP *stateless*: the `initialize` /
//! `notifications/initialized` handshake was **removed**, and every request now
//! carries its own protocol version, client info and capabilities in `_meta`
//! (`io.modelcontextprotocol/*`), mirrored into HTTP headers.
//!
//! Servers in the field still speak the older handshake-based revisions, so the
//! client here is *dual-era*, exactly as the spec's compatibility matrix
//! prescribes:
//!
//! 1. Send a modern stateless `tools/list`.
//! 2. On `400`, inspect the body. A recognised modern JSON-RPC error means a
//!    modern server: `UnsupportedProtocolVersionError` (`-32022`) carries the
//!    versions it does support, so retry with one of those.
//! 3. A `400`/`404`/`405` *without* a modern error body means a legacy server:
//!    fall back to `initialize` -> `notifications/initialized` -> `tools/list`.

use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::manifest::{ServerManifest, ToolManifest, Transport};

/// The protocol revision mcpwn speaks first.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Legacy revisions understood by the `initialize` fallback, newest first.
pub const LEGACY_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];

/// `UnsupportedProtocolVersionError`, per the 2026-07-28 error-code allocation.
const ERR_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// `HeaderMismatchError`.
const ERR_HEADER_MISMATCH: i64 = -32020;
/// `MissingRequiredClientCapabilityError`.
const ERR_MISSING_CAPABILITY: i64 = -32021;

/// What happened when we tried to list a server's tools.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "enumeration", rename_all = "kebab-case")]
pub enum Enumeration {
    /// Tools were retrieved. `protocol` is the revision that actually worked.
    Enumerated { protocol: String },
    /// Cannot be done without executing local code. Deliberately not attempted.
    NotPossible { reason: String },
    /// Tried and failed: unreachable, timed out, malformed, or not speaking MCP.
    Failed { reason: String },
}

impl Enumeration {
    pub fn is_enumerated(&self) -> bool {
        matches!(self, Enumeration::Enumerated { .. })
    }

    /// One-line description for the terminal and for warnings.
    pub fn describe(&self) -> String {
        match self {
            Enumeration::Enumerated { protocol } => format!("enumerated via {protocol}"),
            Enumeration::NotPossible { reason } | Enumeration::Failed { reason } => reason.clone(),
        }
    }
}

/// One server plus the outcome of enumerating it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnumeratedServer {
    pub server: ServerManifest,
    #[serde(flatten)]
    pub outcome: Enumeration,
}

impl EnumeratedServer {
    pub fn tool_count(&self) -> usize {
        self.server.tools.len()
    }
}

/// Static enumeration: HTTP servers are queried, stdio servers are not touched.
///
/// Named for the mode it implements so a future live/spawning mode can sit
/// beside it without renaming this one.
#[derive(Debug, Clone)]
pub struct StaticEnumerator {
    timeout: Duration,
    client_name: String,
    client_version: String,
    /// Extra headers sent with every request, e.g. `Authorization`. Applied to
    /// every HTTP server in the run.
    headers: Vec<(String, String)>,
}

impl Default for StaticEnumerator {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            client_name: crate::NAME.to_owned(),
            client_version: crate::VERSION.to_owned(),
            headers: Vec::new(),
        }
    }
}

impl StaticEnumerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total time budget per HTTP request.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Extra headers sent with every request. Use [`parse_headers`] to build
    /// them from `--header` arguments.
    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    /// Enumerate every server, consuming the manifests and returning them
    /// enriched. Never fails: each server carries its own outcome.
    pub fn enumerate_all(&self, servers: Vec<ServerManifest>) -> Vec<EnumeratedServer> {
        servers
            .into_iter()
            .map(|server| self.enumerate(server))
            .collect()
    }

    /// Enumerate one server.
    pub fn enumerate(&self, mut server: ServerManifest) -> EnumeratedServer {
        let url = match server.transport.as_ref() {
            Some(Transport::Http { url }) => url.clone(),
            // The safety rule: a stdio server is never launched.
            Some(Transport::Stdio { .. }) => {
                return EnumeratedServer {
                    server,
                    outcome: Enumeration::NotPossible {
                        reason: "stdio server: live enumeration required, not implemented"
                            .to_owned(),
                    },
                }
            }
            Some(Transport::Unknown) | None => {
                return EnumeratedServer {
                    server,
                    outcome: Enumeration::NotPossible {
                        reason: "no usable transport declared in the config".to_owned(),
                    },
                }
            }
        };

        match self.list_tools(&url) {
            Ok((tools, protocol)) => {
                server.tools = tools;
                EnumeratedServer {
                    server,
                    outcome: Enumeration::Enumerated { protocol },
                }
            }
            Err(reason) => EnumeratedServer {
                server,
                outcome: Enumeration::Failed { reason },
            },
        }
    }

    /// Dual-era `tools/list`. Returns the tools and the revision that worked.
    fn list_tools(&self, url: &str) -> Result<(Vec<ToolManifest>, String), String> {
        // 1. Modern, stateless.
        match self.modern_tools_list(url, PROTOCOL_VERSION) {
            Probe::Ok(value) => return Ok((parse_tools(&value)?, PROTOCOL_VERSION.to_owned())),
            // 2. A modern server that refuses this revision tells us what it takes.
            Probe::ModernVersionMismatch(supported) => {
                if let Some(version) = supported.iter().find(|v| v.as_str() == PROTOCOL_VERSION) {
                    // Same revision back: nothing further to try.
                    return Err(format!(
                        "server rejected its own advertised version {version}"
                    ));
                }
                for version in &supported {
                    if LEGACY_PROTOCOL_VERSIONS.contains(&version.as_str()) {
                        // Advertised version predates statelessness: use the handshake.
                        return self
                            .legacy_tools_list(url, version)
                            .map(|tools| (tools, version.clone()));
                    }
                    if let Probe::Ok(value) = self.modern_tools_list(url, version) {
                        return Ok((parse_tools(&value)?, version.clone()));
                    }
                }
                return Err(format!(
                    "no mutually supported protocol version (server offers: {})",
                    if supported.is_empty() {
                        "none".to_owned()
                    } else {
                        supported.join(", ")
                    }
                ));
            }
            Probe::ModernError(message) => return Err(message),
            Probe::Fatal(message) => return Err(message),
            // 3. Not a modern server: fall back to the handshake.
            Probe::MaybeLegacy => {}
        }

        let mut last = String::from("no legacy protocol version accepted");
        for version in LEGACY_PROTOCOL_VERSIONS {
            match self.legacy_tools_list(url, version) {
                Ok(tools) => return Ok((tools, (*version).to_owned())),
                Err(err) => last = err,
            }
        }
        Err(with_sse_hint(url, last))
    }

    /// A single stateless `tools/list` (revision 2026-07-28 and later).
    fn modern_tools_list(&self, url: &str, version: &str) -> Probe {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "_meta": self.request_meta(version) }
        });

        let (status, text) = match self.post(url, &body, Some(version), "tools/list") {
            Ok(pair) => pair,
            Err(err) => return Probe::Fatal(err),
        };

        // Per the spec's backward-compatibility rules, these statuses mean
        // "legacy server" *only* when the body is not a modern JSON-RPC error.
        let ambiguous = matches!(status, 400 | 404 | 405);
        let Some(message) = decode_jsonrpc(&text) else {
            return if matches!(status, 401 | 403) {
                // Authentication is era-independent: never fall back on it.
                Probe::Fatal(http_failure(status, &text))
            } else if ambiguous {
                Probe::MaybeLegacy
            } else if status != 200 {
                Probe::Fatal(http_failure(status, &text))
            } else {
                Probe::Fatal(format!(
                    "malformed response: not a JSON-RPC message ({})",
                    snippet(&text)
                ))
            };
        };

        if let Some(error) = message.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            return match code {
                ERR_UNSUPPORTED_PROTOCOL_VERSION => Probe::ModernVersionMismatch(
                    error
                        .get("data")
                        .and_then(|d| d.get("supported"))
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                ),
                ERR_HEADER_MISMATCH | ERR_MISSING_CAPABILITY => Probe::ModernError(format!(
                    "modern server rejected the request: {}",
                    jsonrpc_message(error)
                )),
                // -32601 with a JSON-RPC body still identifies a modern server.
                _ if ambiguous => Probe::MaybeLegacy,
                _ => Probe::ModernError(jsonrpc_message(error)),
            };
        }

        match message.get("result") {
            Some(result) => Probe::Ok(result.clone()),
            None => Probe::Fatal("malformed response: no result and no error".to_owned()),
        }
    }

    /// `initialize` -> `notifications/initialized` -> `tools/list`, for servers
    /// still on a handshake-based revision (2025-11-25 and earlier).
    fn legacy_tools_list(&self, url: &str, version: &str) -> Result<Vec<ToolManifest>, String> {
        let init = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": self.client_name, "version": self.client_version }
            }
        });
        let (status, text) = self.post(url, &init, None, "initialize")?;
        // A non-JSON-RPC body here means the endpoint does not speak MCP at
        // all; blaming `initialize` would point the user at the wrong thing.
        let message = decode_jsonrpc(&text).ok_or_else(|| http_failure(status, &text))?;
        if let Some(error) = message.get("error") {
            return Err(format!("initialize rejected: {}", jsonrpc_message(error)));
        }
        if message.get("result").is_none() {
            return Err("initialize: no result and no error".to_owned());
        }

        // Required by the legacy lifecycle. A server may 202 or 200 it; either
        // way a failure here is not worth aborting on.
        let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let _ = self.post(url, &initialized, None, "notifications/initialized");

        let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} });
        let (status, text) = self.post(url, &list, None, "tools/list")?;
        let message = decode_jsonrpc(&text)
            .ok_or_else(|| format!("tools/list: {}", http_failure(status, &text)))?;
        if let Some(error) = message.get("error") {
            return Err(format!("tools/list rejected: {}", jsonrpc_message(error)));
        }
        let result = message
            .get("result")
            .ok_or_else(|| "tools/list: no result and no error".to_owned())?;
        parse_tools(result)
    }

    fn request_meta(&self, version: &str) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {
                "name": self.client_name,
                "version": self.client_version
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        })
    }

    /// POST one JSON-RPC message. Returns the HTTP status and the body text.
    ///
    /// Non-2xx is *not* an error here: the spec requires reading the body of a
    /// 400 to tell a modern server from a legacy one.
    fn post(
        &self,
        url: &str,
        body: &Value,
        protocol_version: Option<&str>,
        method: &str,
    ) -> Result<(u16, String), String> {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .http_status_as_error(false)
            .user_agent(format!("{}/{}", self.client_name, self.client_version))
            .build();
        let agent: ureq::Agent = config.into();

        let mut request = agent
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            // Mirrored body field, REQUIRED on every modern POST.
            .header("mcp-method", method);
        if let Some(version) = protocol_version {
            request = request.header("mcp-protocol-version", version);
        }
        // User-supplied last, but they can never collide with the protocol
        // headers above: `parse_header` refuses those names.
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let payload = serde_json::to_string(body)
            .map_err(|err| format!("could not encode the request: {err}"))?;
        let mut response = request
            .send(&payload)
            .map_err(|err| describe_transport_error(&err))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|err| format!("could not read the response body: {err}"))?;
        Ok((status, text))
    }
}

/// Outcome of one modern probe.
enum Probe {
    /// A JSON-RPC `result`.
    Ok(Value),
    /// `UnsupportedProtocolVersionError` with the versions the server supports.
    ModernVersionMismatch(Vec<String>),
    /// A modern server that refused for another reason. Do not fall back.
    ModernError(String),
    /// Not a modern server: try the `initialize` handshake.
    MaybeLegacy,
    /// Transport-level or unrecoverable failure.
    Fatal(String),
}

fn describe_transport_error(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Timeout(_) => "timed out".to_owned(),
        ureq::Error::ConnectionFailed => {
            "connection failed (unreachable host or TLS failure)".to_owned()
        }
        ureq::Error::Io(io) => format!("unreachable: {io}"),
        other => other.to_string(),
    }
}

fn jsonrpc_message(error: &Value) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unspecified error")
        .to_owned()
}

/// Decode a response body that may be a bare JSON object or an SSE stream.
///
/// Streamable HTTP lets the server answer with either `application/json` or
/// `text/event-stream`; a client MUST support both. For a single request the
/// SSE stream carries optional notifications and then the response, so the last
/// `data:` payload holding an `id` is the one we want.
fn decode_jsonrpc(text: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if is_jsonrpc(&value) {
            return Some(value);
        }
    }

    let mut found = None;
    for line in text.lines() {
        // SSE comment lines (keep-alives) start with a colon and carry no data.
        let Some(payload) = line.strip_prefix("data:") else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<Value>(payload.trim()) {
            if value.get("id").is_some() && is_jsonrpc(&value) {
                found = Some(value);
            }
        }
    }
    found
}

/// Whether a JSON value is actually a JSON-RPC message.
///
/// Being an object is not enough: an HTTP error page can be JSON too. A gateway
/// answering `{"error": "Missing Authorization header"}` must be reported as
/// what it is, not mistaken for a protocol-level error with no message.
fn is_jsonrpc(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.contains_key("jsonrpc") {
        return true;
    }
    object.contains_key("result")
        || object
            .get("error")
            .is_some_and(|e| e.get("code").is_some_and(Value::is_i64))
}

/// A one-line, bounded excerpt of a response body, for error messages.
fn snippet(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > 160 {
        format!("{}…", collapsed.chars().take(160).collect::<String>())
    } else {
        collapsed
    }
}

/// An `/sse` endpoint is the deprecated 2024-11-05 HTTP+SSE transport, which
/// needs a GET and an `endpoint` event. mcpwn does not implement it, and the
/// resulting 405 is baffling without this hint.
fn with_sse_hint(url: &str, error: String) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    if path.trim_end_matches('/').ends_with("/sse") {
        format!("{error} — this looks like the deprecated HTTP+SSE endpoint; try the Streamable HTTP one (often /mcp)")
    } else {
        error
    }
}

/// Describe a non-JSON-RPC HTTP failure, keeping the status and what the server
/// actually said — both are what a user needs to act on.
fn http_failure(status: u16, body: &str) -> String {
    let hint = match status {
        401 | 403 => " (the endpoint requires authentication)",
        404 => " (no MCP endpoint at this path?)",
        _ => "",
    };
    // Quoting 160 characters of an HTML error page tells the user nothing.
    let excerpt = if body.trim_start().starts_with('<') {
        "(HTML page, not a JSON-RPC response)".to_owned()
    } else {
        snippet(body)
    };
    if excerpt.is_empty() {
        format!("HTTP {status}{hint}")
    } else {
        format!("HTTP {status}{hint}: {excerpt}")
    }
}

/// Read the tool list out of a `tools/list` result.
///
/// The result shape is stable across every revision that matters here: a
/// `tools` array of `{name, description?, inputSchema}`. 2026-07-28 added
/// `ttlMs` / `cacheScope` alongside it, which are caching hints we ignore.
fn parse_tools(result: &Value) -> Result<Vec<ToolManifest>, String> {
    let Some(items) = result.get("tools") else {
        return Err("malformed tools/list result: no `tools` field".to_owned());
    };
    let Some(items) = items.as_array() else {
        return Err("malformed tools/list result: `tools` is not an array".to_owned());
    };

    let mut tools = Vec::with_capacity(items.len());
    for item in items {
        let Some(object) = item.as_object() else {
            // One bad entry must not lose the others.
            continue;
        };
        let Some(name) = object.get("name").and_then(Value::as_str) else {
            continue;
        };

        let mut tool = ToolManifest::new(name);
        tool.description = object
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // Kept verbatim: analysing it is `analysis::schema`'s job, and rewriting
        // it here would destroy the very anomalies we later look for.
        tool.input_schema = object.get("inputSchema").cloned();
        tool.extra = object
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "name" | "description" | "inputSchema"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Map<String, Value>>();

        tools.push(tool);
    }
    Ok(tools)
}

/// Headers mcpwn sets itself. A user override would break the protocol or the
/// era detection, so these are refused rather than silently ignored.
const RESERVED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "mcp-protocol-version",
    "mcp-method",
    "content-length",
    "host",
];

/// Parse one `--header 'Name: Value'` argument, curl-style.
///
/// Error messages name the header but **never quote its value**: it is usually
/// a bearer token, and an error message ends up in terminals, logs and CI
/// output.
pub fn parse_header(raw: &str) -> crate::Result<(String, String)> {
    let Some((name, value)) = raw.split_once(':') else {
        return Err(crate::Error::header(
            None,
            "expected `Name: Value` (for example `Authorization: Bearer …`)",
        ));
    };

    let name = name.trim();
    if name.is_empty() {
        return Err(crate::Error::header(None, "the header name is empty"));
    }
    // RFC 9110 token: the characters a field name may contain.
    if !name.chars().all(is_token_char) {
        return Err(crate::Error::header(
            Some(name.to_owned()),
            "the header name contains characters that are not allowed",
        ));
    }
    if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(crate::Error::header(
            Some(name.to_owned()),
            "this header is set by mcpwn itself and cannot be overridden",
        ));
    }

    // RFC 9110: optional whitespace around a field value is separator, not
    // value — on both sides.
    let value = value.trim();
    if value.is_empty() {
        return Err(crate::Error::header(
            Some(name.to_owned()),
            "the header value is empty",
        ));
    }
    // A CR or LF in a value is header injection; reject it here rather than
    // relying on the HTTP client to notice.
    if value.chars().any(|c| c.is_control()) {
        return Err(crate::Error::header(
            Some(name.to_owned()),
            "the header value contains control characters",
        ));
    }

    Ok((name.to_owned(), value.to_owned()))
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// Parse every `--header` argument, failing on the first bad one.
pub fn parse_headers<S: AsRef<str>>(raw: &[S]) -> crate::Result<Vec<(String, String)>> {
    raw.iter().map(|r| parse_header(r.as_ref())).collect()
}

/// Build the same internal server type the discovery/loading path produces,
/// from a bare endpoint URL.
///
/// This is the convergence point for the direct-endpoint entry: after this, an
/// endpoint given on the command line and a server read out of a config file
/// are the same value and take the same code path.
pub fn server_from_url(url: &str) -> crate::Result<ServerManifest> {
    let url = validate_endpoint(url)?;
    let mut server = ServerManifest::new(endpoint_label(&url));
    server.origin = Some(url.clone());
    server.transport = Some(Transport::Http { url });
    Ok(server)
}

/// Check that `url` is a well-formed `http`/`https` endpoint.
///
/// Deliberately a light syntactic check rather than a full URL parser: it
/// catches the mistakes a user actually makes (a bare host, a typo'd scheme, a
/// `file://` path) without pulling in a parsing dependency. Anything subtler is
/// caught by the HTTP client when the request is made.
pub fn validate_endpoint(url: &str) -> crate::Result<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(crate::Error::endpoint(url, "the URL is empty"));
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(crate::Error::endpoint(
            url,
            "the URL contains whitespace or control characters",
        ));
    }

    let lower = trimmed.to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &trimmed["https://".len()..]
    } else if lower.starts_with("http://") {
        &trimmed["http://".len()..]
    } else {
        let scheme = trimmed.split("://").next().unwrap_or(trimmed);
        return Err(crate::Error::endpoint(
            url,
            format!("expected an http:// or https:// URL, got `{scheme}`"),
        ));
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Strip any userinfo before checking the host.
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return Err(crate::Error::endpoint(url, "the URL has no host"));
    }
    if host.starts_with(':') {
        return Err(crate::Error::endpoint(url, "the URL has no host"));
    }

    Ok(trimmed.to_owned())
}

/// A short, readable server name derived from the endpoint: `host[:port]/path`.
fn endpoint_label(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let label = after_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(after_scheme);
    label.trim_end_matches('/').to_owned()
}

/// Read a tool list from a manifest file sitting next to the config, without
/// running anything.
///
/// **Not implemented.** No MCP client writes such a file today and no location
/// is standardised, so there is nothing to read. If one appears, this is where
/// it plugs in — it is the only way a stdio server could ever be enumerated
/// while keeping the no-execution guarantee.
pub fn tools_from_local_manifest(_server: &ServerManifest) -> Option<Vec<ToolManifest>> {
    None
}
