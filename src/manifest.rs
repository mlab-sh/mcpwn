//! In-memory model of an MCP server and the three surfaces it exposes: tools,
//! prompts and resources.
//!
//! Parsing (from `mcp.json`, `claude_desktop_config.json`, a `tools/list`
//! capture, ...) is **not implemented yet**: only the shape is fixed here so
//! the rest of the engine can be written against it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which of a server's three model-visible surfaces a [`ToolRef`] points at.
///
/// Tools are the default because they were the only surface mcpwn knew about
/// first, and because serialising the common case would churn every report and
/// every lock file for no reader's benefit.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum SubjectKind {
    #[default]
    Tool,
    Prompt,
    Resource,
}

impl SubjectKind {
    pub fn slug(self) -> &'static str {
        match self {
            SubjectKind::Tool => "tool",
            SubjectKind::Prompt => "prompt",
            SubjectKind::Resource => "resource",
        }
    }

    fn is_tool(&self) -> bool {
        matches!(self, SubjectKind::Tool)
    }
}

/// A stable, cheap-to-clone pointer to one tool, prompt or resource of one
/// server.
///
/// This is what [`crate::finding::Finding`] carries around, so it must stay
/// small and self-describing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ToolRef {
    /// The server the subject belongs to, as named by the client config.
    pub server: String,
    /// The tool name, prompt name or resource URI, as advertised by the server.
    pub tool: String,
    /// Which surface `tool` names. Absent from serialised output for tools, so
    /// existing reports and lock files keep their shape.
    #[serde(default, skip_serializing_if = "SubjectKind::is_tool")]
    pub kind: SubjectKind,
}

impl ToolRef {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            kind: SubjectKind::Tool,
        }
    }

    /// A pointer to one prompt of a server.
    pub fn prompt(server: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: name.into(),
            kind: SubjectKind::Prompt,
        }
    }

    /// A pointer to one resource of a server, named by its URI.
    pub fn resource(server: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: uri.into(),
            kind: SubjectKind::Resource,
        }
    }
}

impl std::fmt::Display for ToolRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirrors the protocol method that lists the surface, so a reader who
        // knows MCP can tell at a glance which list to go look in.
        match self.kind {
            SubjectKind::Tool => write!(f, "{}::{}", self.server, self.tool),
            SubjectKind::Prompt => write!(f, "{}::prompts/{}", self.server, self.tool),
            SubjectKind::Resource => write!(f, "{}::resources/{}", self.server, self.tool),
        }
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
        /// Environment overrides declared in the config. `BTreeMap` so the
        /// order is stable in reports.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
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
    /// Prompt templates the server offers. Their text reaches the model the
    /// same way a tool description does, so they are analysed the same way.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<PromptManifest>,
    /// Resources the server offers, including URI templates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceManifest>,
}

impl ServerManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            origin: None,
            transport: None,
            tools: Vec::new(),
            prompts: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn tool_ref(&self, tool: &ToolManifest) -> ToolRef {
        ToolRef::new(&self.name, &tool.name)
    }

    pub fn prompt_ref(&self, prompt: &PromptManifest) -> ToolRef {
        ToolRef::prompt(&self.name, &prompt.name)
    }

    pub fn resource_ref(&self, resource: &ResourceManifest) -> ToolRef {
        ToolRef::resource(&self.name, &resource.uri)
    }
}

/// One tool advertised by a server: the primary attack surface.
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

/// One prompt template advertised by a server.
///
/// A prompt is not a passive document: the client renders it into the
/// conversation, usually because the user picked it from a menu, and every
/// string here is read by the model exactly like a tool description is. The
/// arguments carry descriptions too, and those are just as good a place to hide
/// an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptManifest {
    pub name: String,
    /// Human-facing title, shown in whatever menu the client offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Free-form natural language read by the model.
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
    /// Anything else the server sent, kept verbatim for rules to inspect.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, Value>,
}

impl PromptManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: String::new(),
            arguments: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

/// One argument of a prompt template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

impl PromptArgument {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            required: false,
        }
    }
}

/// One resource advertised by a server, or one template for a family of them.
///
/// Resource contents are fetched on demand and dropped into the conversation,
/// which makes a resource a first-class ingest point: whoever controls what it
/// returns controls text the model will read. What is listed here is the
/// *advertisement*, never the contents; mcpwn does not call `resources/read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceManifest {
    /// `uri` for a concrete resource, `uriTemplate` for a template.
    pub uri: String,
    /// Whether `uri` is an RFC 6570 template rather than a fixed URI.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub template: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Free-form natural language read by the model.
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Anything else the server sent, kept verbatim for rules to inspect.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, Value>,
}

impl ResourceManifest {
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            template: false,
            name: String::new(),
            title: None,
            description: String::new(),
            mime_type: None,
            extra: serde_json::Map::new(),
        }
    }

    /// The same, for an entry from `resources/templates/list`.
    pub fn template(uri_template: impl Into<String>) -> Self {
        Self {
            template: true,
            ..Self::new(uri_template)
        }
    }

    /// The URI scheme, lower-cased, when the URI has one.
    pub fn scheme(&self) -> Option<String> {
        let (scheme, _) = self.uri.split_once(':')?;
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return None;
        }
        Some(scheme.to_ascii_lowercase())
    }
}

impl Transport {
    /// Short description used in inventory output.
    pub fn summary(&self) -> String {
        match self {
            Transport::Stdio { command, args, .. } => {
                if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                }
            }
            Transport::Http { url } => url.clone(),
            Transport::Unknown => "(unknown transport)".to_owned(),
        }
    }
}

/// Parse a captured `tools/list` response into a server manifest.
///
/// Not implemented yet: see [`crate::loading::enumerate_tools`] for why tool
/// enumeration is a separate step from config loading.
pub fn parse_tools_list(_server: &str, _raw: &str) -> crate::Result<ServerManifest> {
    todo!("manifest: parse a tools/list capture into a ServerManifest")
}
