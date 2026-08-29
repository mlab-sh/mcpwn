//! Calling a tool on a live server, over either transport.
//!
//! This is the boundary C2 sits on. Everything above it decides *what* to send;
//! this decides how to get it there, counts it against the engagement's budget,
//! and writes it to the transcript.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::audit::stdio::StdioSession;
use crate::enumerate::PROTOCOL_VERSION;
use crate::manifest::ToolManifest;

/// What one tool call produced.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    /// Every piece of text the server returned, flattened for oracle matching:
    /// content blocks, structured content, and the error message if any.
    pub text: String,
    /// The raw JSON-RPC message, for the transcript.
    pub raw: Value,
    /// The server reported the call as failed.
    pub is_error: bool,
    pub duration: Duration,
}

impl CallOutcome {
    fn from_message(message: Value, duration: Duration) -> Self {
        let mut text = String::new();
        if let Some(result) = message.get("result") {
            if let Some(content) = result.get("content").and_then(Value::as_array) {
                for block in content {
                    if let Some(chunk) = block.get("text").and_then(Value::as_str) {
                        text.push_str(chunk);
                        text.push('\n');
                    }
                }
            }
            if let Some(structured) = result.get("structuredContent") {
                text.push_str(&structured.to_string());
                text.push('\n');
            }
            // Some servers put everything in the result with no content block.
            if text.is_empty() {
                text.push_str(&result.to_string());
            }
        }
        if let Some(error) = message.get("error") {
            text.push_str(&error.to_string());
        }

        let is_error = message.get("error").is_some()
            || message
                .pointer("/result/isError")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        Self {
            text,
            raw: message,
            is_error,
            duration,
        }
    }
}

/// Something that can list and call tools on one target.
pub trait ToolCaller: std::fmt::Debug {
    /// A label for the transcript.
    fn target(&self) -> String;

    fn list_tools(&mut self) -> Result<Vec<ToolManifest>, String>;

    fn call(&mut self, tool: &str, arguments: &Value) -> Result<CallOutcome, String>;
}

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------

/// Calls tools on a locally launched server.
#[derive(Debug)]
pub struct StdioCaller {
    session: StdioSession,
    handshaken: bool,
    target: String,
}

impl std::fmt::Debug for StdioSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StdioSession")
    }
}

impl StdioCaller {
    pub fn spawn(
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<Self, String> {
        Ok(Self {
            session: StdioSession::spawn(command, args, env, timeout)?,
            handshaken: false,
            target: format!("stdio:{command} {}", args.join(" ")),
        })
    }

    /// The legacy handshake, performed once and only if the modern path failed.
    fn handshake(&mut self) -> Result<(), String> {
        if self.handshaken {
            return Ok(());
        }
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": crate::NAME, "version": crate::VERSION }
        });
        let message = self.session.request("initialize", params)?;
        if message.get("result").is_none() {
            return Err(format!(
                "initialize rejected: {}",
                message
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified error")
            ));
        }
        self.session
            .notify(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        self.handshaken = true;
        Ok(())
    }

    /// Try the stateless call first, then the handshake, as on HTTP.
    fn request(&mut self, method: &str, mut params: Value) -> Result<Value, String> {
        if !self.handshaken {
            let mut modern = params.clone();
            if let Some(object) = modern.as_object_mut() {
                object.insert("_meta".to_owned(), meta());
            }
            match self.session.request(method, modern) {
                Ok(message) if message.get("result").is_some() => return Ok(message),
                Err(err) if self.session.is_finished() => return Err(err),
                _ => {}
            }
            self.handshake()?;
        }
        if let Some(object) = params.as_object_mut() {
            object.remove("_meta");
        }
        self.session.request(method, params)
    }
}

impl ToolCaller for StdioCaller {
    fn target(&self) -> String {
        self.target.clone()
    }

    fn list_tools(&mut self) -> Result<Vec<ToolManifest>, String> {
        let message = self.request("tools/list", json!({}))?;
        let result = message
            .get("result")
            .ok_or_else(|| "tools/list returned no result".to_owned())?;
        crate::enumerate::parse_tools(result)
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Result<CallOutcome, String> {
        let started = Instant::now();
        let message = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )?;
        Ok(CallOutcome::from_message(message, started.elapsed()))
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// Calls tools on a remote endpoint.
#[derive(Debug)]
pub struct HttpCaller {
    url: String,
    headers: Vec<(String, String)>,
    timeout: Duration,
    /// Set once the endpoint has told us which era it speaks.
    legacy_session: Option<Option<String>>,
}

impl HttpCaller {
    pub fn new(url: &str, headers: Vec<(String, String)>, timeout: Duration) -> Self {
        Self {
            url: url.to_owned(),
            headers,
            timeout,
            legacy_session: None,
        }
    }

    fn agent(&self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .http_status_as_error(false)
            .user_agent(format!("{}-audit/{}", crate::NAME, crate::VERSION))
            .build()
            .into()
    }

    fn post(&self, body: &Value, session: Option<&str>, modern: bool) -> Result<Value, String> {
        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let mut request = self
            .agent()
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-method", method);
        if modern {
            request = request.header("mcp-protocol-version", PROTOCOL_VERSION);
        }
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let payload =
            serde_json::to_string(body).map_err(|err| format!("could not encode: {err}"))?;
        let mut response = request
            .send(&payload)
            .map_err(|err| format!("request failed: {err}"))?;
        let status = response.status().as_u16();
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let text = read_bounded(response.body_mut());

        let message = decode(&text).ok_or_else(|| format!("HTTP {status}: no JSON-RPC message"))?;
        if let Some(session_id) = session_id {
            // Remember a session the server minted, for the legacy path.
            if let Some(slot) = self.legacy_session.as_ref() {
                let _ = slot;
            }
            return Ok(json!({ "__session": session_id, "message": message }));
        }
        Ok(json!({ "message": message }))
    }

    /// One request, resolving the protocol era on first use.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        // Modern: stateless, `_meta` in the body.
        if self.legacy_session.is_none() {
            let mut modern_params = params.clone();
            if let Some(object) = modern_params.as_object_mut() {
                object.insert("_meta".to_owned(), meta());
            }
            let body = json!({
                "jsonrpc": "2.0", "id": 1, "method": method, "params": modern_params
            });
            if let Ok(envelope) = self.post(&body, None, true) {
                let message = envelope["message"].clone();
                if message.get("result").is_some() {
                    return Ok(message);
                }
            }
            // Not modern: do the handshake once and remember the session.
            self.legacy_session = Some(self.initialize()?);
        }

        let session = self.legacy_session.clone().flatten();
        let body = json!({ "jsonrpc": "2.0", "id": 2, "method": method, "params": params });
        Ok(self.post(&body, session.as_deref(), false)?["message"].clone())
    }

    fn initialize(&self) -> Result<Option<String>, String> {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": crate::NAME, "version": crate::VERSION }
            }
        });
        let envelope = self.post(&body, None, false)?;
        if envelope["message"].get("result").is_none() {
            return Err(format!(
                "initialize rejected: {}",
                envelope["message"]
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified error")
            ));
        }
        let session = envelope
            .get("__session")
            .and_then(Value::as_str)
            .map(str::to_owned);

        // Required by the legacy lifecycle; a failure here is not fatal.
        let _ = self.post(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            session.as_deref(),
            false,
        );
        Ok(session)
    }
}

impl ToolCaller for HttpCaller {
    fn target(&self) -> String {
        self.url.clone()
    }

    fn list_tools(&mut self) -> Result<Vec<ToolManifest>, String> {
        let message = self.request("tools/list", json!({}))?;
        let result = message
            .get("result")
            .ok_or_else(|| "tools/list returned no result".to_owned())?;
        crate::enumerate::parse_tools(result)
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Result<CallOutcome, String> {
        let started = Instant::now();
        let message = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )?;
        Ok(CallOutcome::from_message(message, started.elapsed()))
    }
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": { "name": crate::NAME, "version": crate::VERSION },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn read_bounded(body: &mut ureq::Body) -> String {
    use std::io::Read;
    let mut buffer = Vec::new();
    let _ = body
        .as_reader()
        .take(4 * 1024 * 1024)
        .read_to_end(&mut buffer);
    String::from_utf8_lossy(&buffer).into_owned()
}

/// Decode a JSON-RPC message from a plain body or an SSE frame.
fn decode(text: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        if value.get("result").is_some() || value.get("error").is_some() {
            return Some(value);
        }
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|payload| serde_json::from_str::<Value>(payload.trim()).ok())
        .find(|value| value.get("result").is_some() || value.get("error").is_some())
}
