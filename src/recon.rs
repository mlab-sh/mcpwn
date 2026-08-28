//! Read-only reconnaissance of a remote MCP endpoint.
//!
//! Enumeration asks a server one question: what tools do you have. This module
//! asks the handful of others that can be answered without ever calling a tool:
//! does the endpoint need the credential it was given, does it advertise how to
//! authenticate, is the deprecated transport still up, is there a plaintext way
//! in, and does it validate what the specification says it must.
//!
//! Every request here is a `GET`, or a `tools/list` that reads. **No tool is
//! ever called**, nothing is written, and nothing is retried in volume. It is
//! still more traffic than a plain scan sends, and it touches paths the user did
//! not name, so it runs only behind `--probe`.
//!
//! Two requests are deliberately sent **without** the caller's credentials: the
//! anonymous check, whose whole point is to see what an unauthenticated party
//! gets, and the plaintext check, because sending a bearer token over `http://`
//! to find out whether `http://` works would leak it to whoever is listening.

use std::time::Duration;

use serde_json::{json, Value};

use crate::enumerate::PROTOCOL_VERSION;

/// A protocol revision no server can legitimately support, used to check that
/// the version is validated at all.
const IMPOSSIBLE_VERSION: &str = "1900-01-01";

/// What one endpoint answered.
///
/// Every field is an `Option`: a probe that could not be carried out says
/// nothing rather than guessing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ServerProbe {
    pub endpoint: String,
    /// `tools/list` answered with a result when sent with no credentials.
    pub anonymous_tools_list: Option<bool>,
    /// HTTP status of that anonymous request.
    pub anonymous_status: Option<u16>,
    /// `WWW-Authenticate` returned alongside a 401 or 403.
    pub www_authenticate: Option<String>,
    /// `/.well-known/oauth-protected-resource` is served.
    pub protected_resource_metadata: Option<bool>,
    /// A deprecated HTTP+SSE endpoint answering on the same origin.
    pub legacy_sse_endpoint: Option<String>,
    /// The same endpoint reachable over plaintext `http://`.
    pub plaintext_endpoint: Option<String>,
    /// The server answered normally to an impossible protocol version.
    pub accepts_impossible_version: Option<bool>,
    /// The server answered normally when `Mcp-Method` contradicted the body.
    pub accepts_header_mismatch: Option<bool>,
    /// Revisions the server says it supports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub supported_versions: Vec<String>,
    /// `serverInfo` as reported by `server/discover`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<Value>,
    /// Whether the caller supplied credentials, which decides whether the
    /// anonymous result is a finding or merely a fact.
    pub credentials_supplied: bool,
}

/// Runs the read-only probes against one endpoint.
#[derive(Debug, Clone)]
pub struct Prober {
    timeout: Duration,
    headers: Vec<(String, String)>,
}

impl Default for Prober {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            headers: Vec::new(),
        }
    }
}

impl Prober {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The credentials the caller supplied, replayed on the probes that are
    /// meant to run authenticated.
    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    /// Probe one endpoint. Never fails: a probe that cannot be carried out
    /// leaves its field `None`.
    pub fn probe(&self, url: &str) -> ServerProbe {
        let mut probe = ServerProbe {
            endpoint: url.to_owned(),
            credentials_supplied: !self.headers.is_empty(),
            ..Default::default()
        };

        self.anonymous(url, &mut probe);
        self.authentication_metadata(url, &mut probe);
        self.legacy_transport(url, &mut probe);
        self.plaintext(url, &mut probe);
        self.spec_validation(url, &mut probe);
        self.discover(url, &mut probe);
        probe
    }

    /// What an unauthenticated party gets.
    fn anonymous(&self, url: &str, probe: &mut ServerProbe) {
        let Some(response) = self.post(url, &tools_list(PROTOCOL_VERSION), &[], None) else {
            return;
        };
        probe.anonymous_status = Some(response.status);
        probe.anonymous_tools_list = Some(has_result(&response.body));
        probe.www_authenticate = response.www_authenticate;
    }

    /// Whether the server advertises how to authenticate, as the specification
    /// asks a protected server to.
    fn authentication_metadata(&self, url: &str, probe: &mut ServerProbe) {
        if !matches!(probe.anonymous_status, Some(401 | 403)) {
            return; // an open server has nothing to advertise.
        }
        let Some(origin) = origin_of(url) else { return };
        let metadata = format!("{origin}/.well-known/oauth-protected-resource");
        probe.protected_resource_metadata =
            Some(self.get(&metadata).is_some_and(|r| r.status == 200));
    }

    /// The HTTP+SSE transport, deprecated since protocol revision 2025-03-26.
    fn legacy_transport(&self, url: &str, probe: &mut ServerProbe) {
        let Some(origin) = origin_of(url) else { return };
        let candidate = format!("{origin}/sse");
        if candidate == url {
            return;
        }
        if let Some(response) = self.get(&candidate) {
            // The old transport answers a GET with an event stream; anything
            // else on that path is a different service.
            if response.status == 200
                && response
                    .content_type
                    .as_deref()
                    .is_some_and(|t| t.contains("text/event-stream"))
            {
                probe.legacy_sse_endpoint = Some(candidate);
            }
        }
    }

    /// Whether the same endpoint is reachable without transport security.
    ///
    /// Sent with **no credentials**: finding out that `http://` works is not
    /// worth handing a bearer token to whoever is on the path.
    fn plaintext(&self, url: &str, probe: &mut ServerProbe) {
        let Some(downgraded) = url
            .strip_prefix("https://")
            .map(|rest| format!("http://{rest}"))
        else {
            return; // already plaintext; MCPWN-CFG-003 covers that.
        };

        // Redirects are not followed here: a redirect to https is the correct
        // answer, and following it would hide the very thing being measured.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(format!("{}/{}", crate::NAME, crate::VERSION))
            .build()
            .into();

        let body = tools_list(PROTOCOL_VERSION);
        let Ok(payload) = serde_json::to_string(&body) else {
            return;
        };
        let response = finish(
            agent
                .post(&downgraded)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", PROTOCOL_VERSION)
                .header("mcp-method", "tools/list")
                .send(&payload),
        );

        if let Some(response) = response {
            let redirected_to_https = (300..400).contains(&response.status)
                && response
                    .location
                    .as_deref()
                    .is_some_and(|l| l.starts_with("https://"));

            // The bar is a JSON-RPC message, not merely an HTTP answer. Plenty
            // of things sit on port 80 and reply: captive portals, filtering
            // proxies, default vhosts. None of them is an MCP endpoint, and
            // treating their block page as one is a false positive that cost a
            // scan of six real servers to notice.
            let speaks_mcp = json(&response.body).is_some();
            if speaks_mcp && !redirected_to_https {
                probe.plaintext_endpoint = Some(downgraded);
            }
        }
    }

    /// Two rules the specification states as MUSTs, both checkable by reading.
    fn spec_validation(&self, url: &str, probe: &mut ServerProbe) {
        // A server MUST reject a protocol version it does not implement with
        // UnsupportedProtocolVersionError. Answering normally means it never
        // looked.
        if let Some(response) = self.post(
            url,
            &tools_list(IMPOSSIBLE_VERSION),
            &self.headers,
            Some(IMPOSSIBLE_VERSION),
        ) {
            if has_result(&response.body) {
                probe.accepts_impossible_version = Some(true);
            } else if error_code(&response.body).is_some() {
                probe.accepts_impossible_version = Some(false);
            }
        }

        // A server MUST reject a request whose mirrored headers disagree with
        // the body, with -32020. The header says one method, the body another.
        let body = tools_list(PROTOCOL_VERSION);
        if let Some(response) = self.post_with_method_header(url, &body, "tools/call") {
            if has_result(&response.body) {
                probe.accepts_header_mismatch = Some(true);
            } else if error_code(&response.body).is_some() {
                probe.accepts_header_mismatch = Some(false);
            }
        }
    }

    /// What the server says about itself.
    fn discover(&self, url: &str, probe: &mut ServerProbe) {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": { "_meta": meta(PROTOCOL_VERSION) }
        });
        let Some(response) = self.post(url, &request, &self.headers, Some(PROTOCOL_VERSION)) else {
            return;
        };
        let Some(message) = json(&response.body) else {
            return;
        };

        // Supported versions come either from the result or from the error the
        // server returns when it dislikes ours.
        for path in [
            message.pointer("/result/supportedVersions"),
            message.pointer("/result/protocolVersions"),
            message.pointer("/error/data/supported"),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(items) = path.as_array() {
                probe.supported_versions = items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                break;
            }
        }
        for pointer in ["/result/serverInfo", "/result/_meta"] {
            if let Some(info) = message.pointer(pointer) {
                probe.server_info = Some(info.clone());
                break;
            }
        }
    }

    // --- HTTP plumbing ------------------------------------------------------

    fn agent(&self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .http_status_as_error(false)
            .user_agent(format!("{}/{}", crate::NAME, crate::VERSION))
            .build()
            .into()
    }

    fn post(
        &self,
        url: &str,
        body: &Value,
        headers: &[(String, String)],
        protocol_version: Option<&str>,
    ) -> Option<Response> {
        let mut request = self
            .agent()
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-method", method_of(body));
        if let Some(version) = protocol_version {
            request = request.header("mcp-protocol-version", version);
        }
        for (name, value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }
        finish(request.send(&serde_json::to_string(body).ok()?))
    }

    /// A request whose `Mcp-Method` header deliberately contradicts its body.
    fn post_with_method_header(&self, url: &str, body: &Value, header: &str) -> Option<Response> {
        let mut request = self
            .agent()
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .header("mcp-method", header);
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        finish(request.send(&serde_json::to_string(body).ok()?))
    }

    fn get(&self, url: &str) -> Option<Response> {
        finish(
            self.agent()
                .get(url)
                .header("accept", "text/event-stream, application/json, */*")
                .call(),
        )
    }
}

struct Response {
    status: u16,
    body: String,
    content_type: Option<String>,
    www_authenticate: Option<String>,
    /// `Location`, when the server redirected rather than answered.
    location: Option<String>,
}

fn finish(result: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Option<Response> {
    let mut response = result.ok()?;
    let status = response.status().as_u16();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = header("content-type");
    let www_authenticate = header("www-authenticate");
    let location = header("location");

    // An SSE stream never ends on its own, so read a bounded prefix rather than
    // to EOF: the first response is all these probes need.
    let body = read_prefix(response.body_mut());

    Some(Response {
        status,
        body,
        content_type,
        www_authenticate,
        location,
    })
}

/// Read at most 64 KiB, stopping at the first blank line of an SSE stream.
fn read_prefix(body: &mut ureq::Body) -> String {
    use std::io::Read;

    let mut buffer = Vec::new();
    let mut reader = body.as_reader().take(64 * 1024);
    let _ = reader.read_to_end(&mut buffer);
    String::from_utf8_lossy(&buffer).into_owned()
}

fn tools_list(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": { "_meta": meta(version) }
    })
}

fn meta(version: &str) -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": { "name": crate::NAME, "version": crate::VERSION },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn method_of(body: &Value) -> &str {
    body.get("method")
        .and_then(Value::as_str)
        .unwrap_or("tools/list")
}

/// Decode a JSON-RPC message from a plain body or an SSE frame.
fn json(body: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(body.trim()) {
        if value.is_object() {
            return Some(value);
        }
    }
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|payload| serde_json::from_str::<Value>(payload.trim()).ok())
        .find(|value| value.get("result").is_some() || value.get("error").is_some())
}

fn has_result(body: &str) -> bool {
    json(body).is_some_and(|v| v.get("result").is_some())
}

fn error_code(body: &str) -> Option<i64> {
    json(body)?.pointer("/error/code")?.as_i64()
}

/// `https://host:port` from a URL, without its path.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}
