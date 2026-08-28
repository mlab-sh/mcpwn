//! In-memory model of an MCP server and the tools it exposes.
//!
//! Parsing (from `mcp.json`, `claude_desktop_config.json`, a `tools/list`
//! capture, ...) is **not implemented yet** — only the shape is fixed here so
//! the rest of the engine can be written against it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A stable, cheap-to-clone pointer to one tool of one server.
///
/// This is what [`crate::finding::Finding`] carries around, so it must stay
/// small and self-describing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ToolRef {
    /// The server the tool belongs to, as named by the client config.
    pub server: String,
    /// The tool name as advertised by the server.
    pub tool: String,
}

impl ToolRef {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
        }
    }
}

impl std::fmt::Display for ToolRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.server, self.tool)
    }
}

/// How a server is launched / reached. Purely descriptive: mcpwn never runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Transport {
    /// Local process spoken to over stdio.
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    /// Remote HTTP / SSE endpoint.
    Http { url: String },
    /// Present in the config but not recognised.
    Unknown,
}

/// One MCP server and everything statically known about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerManifest {
    /// Name under which the client registers this server.
    pub name: String,
    /// Where the manifest was read from (config file, capture, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default)]
    pub tools: Vec<ToolManifest>,
}

impl ServerManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            origin: None,
            transport: None,
            tools: Vec::new(),
        }
    }

    pub fn tool_ref(&self, tool: &ToolManifest) -> ToolRef {
        ToolRef::new(&self.name, &tool.name)
    }
}

/// One tool advertised by a server — the primary attack surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolManifest {
    pub name: String,
    /// Free-form natural language read by the model. The most dangerous field.
    #[serde(default)]
    pub description: String,
    /// JSON Schema describing the tool arguments (`inputSchema` in MCP).
    #[serde(
        default,
        rename = "inputSchema",
        skip_serializing_if = "Option::is_none"
    )]
    pub input_schema: Option<Value>,
    /// Anything else the server sent, kept verbatim for rules to inspect.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, Value>,
}

impl ToolManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            input_schema: None,
            extra: serde_json::Map::new(),
        }
    }
}

/// Parse a set of server manifests out of a raw client config document.
///
/// Not implemented yet.
pub fn parse_client_config(_raw: &str) -> crate::Result<Vec<ServerManifest>> {
    todo!("manifest: parse MCP client config into ServerManifest values")
}

/// Parse a captured `tools/list` response into a server manifest.
///
/// Not implemented yet.
pub fn parse_tools_list(_server: &str, _raw: &str) -> crate::Result<ServerManifest> {
    todo!("manifest: parse a tools/list capture into a ServerManifest")
}
