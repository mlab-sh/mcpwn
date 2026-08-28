//! Step 2 of two: **read** a [`DiscoveredConfig`] and turn it into
//! [`ServerManifest`]s.
//!
//! # The root-key trap
//!
//! There is no shared schema between MCP clients. The key holding the servers
//! changes per client, and so does its *shape*:
//!
//! | Client | Root key | Shape |
//! |---|---|---|
//! | Claude Desktop, Cursor, Windsurf | `mcpServers` | object, name = key |
//! | VS Code | `servers` (or `mcp.servers`) | object, name = key |
//! | Zed | `context_servers` | object, name = key |
//! | Continue | `mcpServers` | **array**, name = `name` field |
//! | Codex | `[mcp_servers.*]` | TOML table |
//!
//! Assuming `mcpServers` everywhere silently returns zero servers for VS Code
//! and Zed: a scanner that reports "nothing to see here" on a config it simply
//! failed to read is worse than one that errors.
//!
//! # v1 limits
//!
//! Only JSON is parsed. TOML (Codex) and YAML (Continue) files are discovered
//! and reported as [`LoadStatus::Unsupported`] with a warning; they are never a
//! hard error. Adding them is a parser and a dependency, not a redesign.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::discovery::{Client, DiscoveredConfig};
use crate::manifest::{ServerManifest, ToolManifest, Transport};

/// What happened when a discovered config was loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum LoadStatus {
    /// Parsed; `servers` is authoritative.
    Parsed,
    /// Format recognised but no parser yet (TOML, YAML). Not an error.
    Unsupported { reason: String },
    /// Read or parse failed. The file is skipped, the scan continues.
    Skipped { reason: String },
}

impl LoadStatus {
    pub fn is_parsed(&self) -> bool {
        matches!(self, LoadStatus::Parsed)
    }
}

/// A discovered config plus whatever could be loaded from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedConfig {
    #[serde(flatten)]
    pub config: DiscoveredConfig,
    #[serde(flatten)]
    pub status: LoadStatus,
    #[serde(default)]
    pub servers: Vec<ServerManifest>,
}

impl LoadedConfig {
    fn new(config: DiscoveredConfig, status: LoadStatus, servers: Vec<ServerManifest>) -> Self {
        Self {
            config,
            status,
            servers,
        }
    }
}

/// Load every discovered config. Never fails: per-file problems are recorded in
/// each [`LoadedConfig::status`] so one bad file cannot abort the inventory.
pub fn load_all(configs: &[DiscoveredConfig]) -> Vec<LoadedConfig> {
    configs.iter().map(load).collect()
}

/// Load one discovered config.
pub fn load(config: &DiscoveredConfig) -> LoadedConfig {
    if !config.format.is_supported() {
        return LoadedConfig::new(
            config.clone(),
            LoadStatus::Unsupported {
                reason: format!("{} parsing is not implemented yet", config.format),
            },
            Vec::new(),
        );
    }

    let raw = match std::fs::read_to_string(&config.path) {
        Ok(raw) => raw,
        Err(err) => {
            return LoadedConfig::new(
                config.clone(),
                LoadStatus::Skipped {
                    reason: describe_io_error(&err),
                },
                Vec::new(),
            )
        }
    };

    match parse_json(&raw, config.client, &config.path) {
        Ok(servers) => LoadedConfig::new(config.clone(), LoadStatus::Parsed, servers),
        Err(err) => LoadedConfig::new(
            config.clone(),
            LoadStatus::Skipped {
                reason: err.to_string(),
            },
            Vec::new(),
        ),
    }
}

/// Only the servers that were actually parsed, flattened across every config.
pub fn servers_of(loaded: &[LoadedConfig]) -> Vec<ServerManifest> {
    loaded
        .iter()
        .flat_map(|l| l.servers.iter().cloned())
        .collect()
}

fn describe_io_error(err: &std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        std::io::ErrorKind::NotFound => "file disappeared between discovery and load".to_owned(),
        _ => err.to_string(),
    }
}

/// The root keys to try for a client, in order.
///
/// [`Client::Unknown`] tries every known key so a hand-written or relocated
/// config still yields something.
fn root_keys(client: Client) -> &'static [&'static str] {
    match client {
        Client::ClaudeDesktop | Client::Cursor | Client::Windsurf | Client::Continue => {
            &["mcpServers"]
        }
        Client::VsCode => &["servers"],
        Client::Zed => &["context_servers"],
        // Codex is TOML and never reaches the JSON parser; listed for completeness.
        Client::Codex => &["mcp_servers"],
        Client::Unknown => &["mcpServers", "servers", "context_servers", "mcp_servers"],
    }
}

/// Parse a JSON client config into server manifests.
pub fn parse_json(raw: &str, client: Client, origin: &Path) -> crate::Result<Vec<ServerManifest>> {
    let doc: Value = serde_json::from_str(raw)?;
    let origin = origin.display().to_string();

    let Some(node) = find_servers_node(&doc, client) else {
        // A config with no server block is valid: a user may have emptied it.
        return Ok(Vec::new());
    };

    match node {
        // Every client but Continue: an object keyed by server name.
        Value::Object(map) => Ok(map
            .iter()
            .map(|(name, entry)| server_from_entry(name, entry, &origin))
            .collect()),
        // Continue: an array whose entries carry their own `name`.
        Value::Array(items) => Ok(items
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let name = entry
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("<unnamed #{i}>"));
                server_from_entry(&name, entry, &origin)
            })
            .collect()),
        other => Err(crate::Error::manifest(format!(
            "server block is a {}, expected an object or an array",
            json_type_name(other)
        ))),
    }
}

/// Find the server block, trying the client's key first and then the nested
/// `mcp.servers` shape VS Code uses inside `settings.json`.
fn find_servers_node(doc: &Value, client: Client) -> Option<&Value> {
    for key in root_keys(client) {
        if let Some(node) = doc.get(key) {
            return Some(node);
        }
    }
    // VS Code `settings.json`: `{"mcp": {"servers": {...}}}`.
    doc.get("mcp")?.get("servers")
}

fn server_from_entry(name: &str, entry: &Value, origin: &str) -> ServerManifest {
    let mut server = ServerManifest::new(name);
    server.origin = Some(origin.to_owned());
    server.transport = Some(transport_from_entry(entry));
    // Config files declare how to *launch* a server, never what it exposes.
    // Tools stay empty until `enumerate_tools` runs.
    server.tools = Vec::<ToolManifest>::new();
    server
}

/// Read the launch method out of one server entry.
///
/// Handles the shapes seen in the wild: a plain `command` string, Zed's nested
/// `command: {path, args}` object, and remote `url` / `serverUrl` entries.
fn transport_from_entry(entry: &Value) -> Transport {
    if let Some(url) = entry
        .get("url")
        .or_else(|| entry.get("serverUrl"))
        .and_then(Value::as_str)
    {
        return Transport::Http {
            url: url.to_owned(),
        };
    }

    let command_node = entry.get("command");
    let (command, nested_args) = match command_node {
        Some(Value::String(s)) => (Some(s.clone()), None),
        Some(Value::Object(obj)) => (
            obj.get("path")
                .or_else(|| obj.get("command"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            obj.get("args"),
        ),
        _ => (None, None),
    };

    match command {
        Some(command) => Transport::Stdio {
            command,
            args: string_list(nested_args.or_else(|| entry.get("args"))),
            env: string_map(entry.get("env")),
        },
        None => Transport::Unknown,
    }
}

fn string_list(node: Option<&Value>) -> Vec<String> {
    node.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn string_map(node: Option<&Value>) -> BTreeMap<String, String> {
    node.and_then(Value::as_object)
        .map(|map: &Map<String, Value>| {
            map.iter()
                .map(|(k, v)| {
                    let value = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), value)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// Tool enumeration lives in [`crate::enumerate`]: config files say how to
// *launch* a server, never what it exposes, so `ServerManifest::tools` is always
// empty after loading. Filling it in is a separate step with its own safety
// rule (no local process is ever spawned).
