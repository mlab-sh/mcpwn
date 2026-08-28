//! Tagging each tool with the roles it can play in an exfiltration chain.
//!
//! * **Source** — reads private state: local files, secrets, environment,
//!   mailbox, database, clipboard.
//! * **Ingest** — brings *untrusted, third-party* content into the context: a
//!   fetched web page, an incoming mail, an issue body. This is the injection
//!   point, the thing that can steer the model.
//! * **Sink** — sends data outward: an arbitrary request, a mail, a webhook, a
//!   published comment.
//!
//! A tool can carry several roles. A shell tool carries source *and* sink on
//! its own.
//!
//! # The tagging is heuristic, and says so
//!
//! It catches the clear cases and misses contrived ones. Every tag records
//! whether it is [`RoleConfidence::Clear`] or [`RoleConfidence::Ambiguous`],
//! and that distinction is carried all the way into the finding's severity —
//! a chain resting on a guess is not reported as a certainty.

use serde::{Deserialize, Serialize};

use crate::analysis::capabilities::{tokenize, Capability};
use crate::analysis::check::ToolContext;
use crate::analysis::normalize;
use crate::analysis::schema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Role {
    Ingest,
    Source,
    Sink,
}

impl Role {
    pub fn slug(self) -> &'static str {
        match self {
            Role::Ingest => "ingest",
            Role::Source => "source",
            Role::Sink => "sink",
        }
    }

    /// The order a toxic flow runs in: injection, then read, then exfiltration.
    pub const CHAIN: [Role; 3] = [Role::Ingest, Role::Source, Role::Sink];
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// How solid a role tag is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleConfidence {
    /// The tool's own name says so.
    Clear,
    /// Inferred from a capability, or from a network tool whose direction could
    /// not be determined. Tagged deliberately, but not something to report as
    /// certain.
    Ambiguous,
}

/// One role a tool can play, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTag {
    pub role: Role,
    pub confidence: RoleConfidence,
    /// Human-readable justification, quoted in the finding.
    pub rationale: String,
}

/// The roles inferred for one tool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTags {
    pub tags: Vec<RoleTag>,
}

impl RoleTags {
    pub fn has(&self, role: Role) -> bool {
        self.tags.iter().any(|t| t.role == role)
    }

    pub fn get(&self, role: Role) -> Option<&RoleTag> {
        self.tags.iter().find(|t| t.role == role)
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Keep the strongest tag per role.
    fn add(&mut self, role: Role, confidence: RoleConfidence, rationale: impl Into<String>) {
        match self.tags.iter_mut().find(|t| t.role == role) {
            Some(existing)
                if existing.confidence == RoleConfidence::Ambiguous
                    && confidence == RoleConfidence::Clear =>
            {
                existing.confidence = RoleConfidence::Clear;
                existing.rationale = rationale.into();
            }
            Some(_) => {}
            None => self.tags.push(RoleTag {
                role,
                confidence,
                rationale: rationale.into(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// THE HEURISTIC TABLES
//
// Roles are not decided by a flat keyword list, because the same verb means
// opposite things depending on what it acts on: `read_file` reads private local
// state (source), `read_wiki_contents` pulls in a third party's text (ingest).
// So the tables are two-dimensional — a verb and an object — and the role falls
// out of the pair.
//
// Everything the tagger knows lives here. Editing these lists is how you tune
// it; there are no keywords buried in the code below.
// ---------------------------------------------------------------------------

/// Verbs that bring data *in*.
pub const INBOUND_VERBS: &[&str] = &[
    "read", "get", "fetch", "list", "load", "open", "browse", "crawl", "scrape", "download",
    "retrieve", "view", "show", "cat", "dump", "lookup", "find", "search", "query", "inspect",
];

/// Verbs that push data *out*.
pub const OUTBOUND_VERBS: &[&str] = &[
    "send", "post", "put", "publish", "upload", "push", "write", "create", "notify", "submit",
    "deliver", "dispatch", "share", "export", "sync", "comment", "reply", "emit", "report",
];

/// Objects that are private to the user or the machine.
pub const PRIVATE_OBJECTS: &[&str] = &[
    "file",
    "files",
    "filesystem",
    "directory",
    "dir",
    "folder",
    "path",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "keychain",
    "password",
    "passwords",
    "token",
    "env",
    "environment",
    "envvar",
    "clipboard",
    "database",
    "db",
    "table",
    "row",
    "inbox",
    "mailbox",
    "contacts",
    "calendar",
    "notes",
    "memory",
    "history",
    "config",
    "settings",
    "ssh",
    "aws",
    "keys",
    "privatekey",
    "dotenv",
];

/// Objects that are third-party content, i.e. attacker-influenceable.
pub const EXTERNAL_OBJECTS: &[&str] = &[
    "url",
    "uri",
    "page",
    "web",
    "website",
    "http",
    "https",
    "html",
    "issue",
    "issues",
    "pr",
    "pull",
    "comment",
    "comments",
    "feed",
    "rss",
    "article",
    "wiki",
    "docs",
    "documentation",
    "readme",
    "repo",
    "repository",
    "remote",
    "endpoint",
    "site",
    "link",
    "thread",
    "ticket",
    "review",
    "content",
    "contents",
    "mail",
    "email",
    "message",
    "messages",
];

/// Description phrases that settle a role on their own.
pub const SOURCE_PHRASES: &[&str] = &[
    "from disk",
    "on the local",
    "local file",
    "the user's file",
    "environment variable",
    "api key",
    "access token",
    "credentials",
    "private key",
    "from the database",
    "clipboard",
];

pub const INGEST_PHRASES: &[&str] = &[
    "from the web",
    "web page",
    "fetch a url",
    "fetches the",
    "downloads the",
    "remote content",
    "third-party",
    "issue body",
    "incoming",
    "returns the content of the page",
];

pub const SINK_PHRASES: &[&str] = &[
    "sends the",
    "sends a",
    "posts the",
    "posts a",
    "publishes",
    "uploads",
    "delivers",
    "http post",
    "webhook",
    "notifies",
];

/// HTTP methods that mean the tool is pushing data out.
const OUTBOUND_METHODS: &[&str] = &["post", "put", "patch", "delete"];
/// HTTP methods that mean the tool is pulling data in.
const INBOUND_METHODS: &[&str] = &["get", "head"];

/// Infer the roles of one tool.
///
/// `capabilities` is what [`crate::analysis::capabilities`] already concluded
/// about this tool — consumed rather than recomputed.
pub fn tag_tool(tool: &ToolContext<'_>, capabilities: &[Capability]) -> RoleTags {
    let mut tags = RoleTags::default();

    let name_tokens = tokenize(&tool.tool.name);
    // The *normalised* description: a zero-width character inside a keyword
    // must not hide the role, exactly as for every other semantic matcher.
    let description = normalize::normalize(&tool.tool.description)
        .cleaned
        .to_ascii_lowercase();

    let param_tokens: Vec<String> = tool
        .tool
        .input_schema
        .as_ref()
        .map(|s| {
            schema::flatten(s)
                .iter()
                .flat_map(|p| tokenize(&p.name))
                .collect()
        })
        .unwrap_or_default();

    let has = |list: &[&str], tokens: &[String]| tokens.iter().any(|t| list.contains(&t.as_str()));
    let inbound_verb = has(INBOUND_VERBS, &name_tokens);
    let outbound_verb = has(OUTBOUND_VERBS, &name_tokens);
    // Objects are looked for in the tool name first, then in its parameters.
    let private_object = has(PRIVATE_OBJECTS, &name_tokens) || has(PRIVATE_OBJECTS, &param_tokens);
    let external_object =
        has(EXTERNAL_OBJECTS, &name_tokens) || has(EXTERNAL_OBJECTS, &param_tokens);

    // --- name-driven tagging: the clear cases ---
    if inbound_verb && private_object && !external_object {
        tags.add(
            Role::Source,
            RoleConfidence::Clear,
            format!("`{}` reads private local state", tool.tool.name),
        );
    }
    if inbound_verb && external_object {
        tags.add(
            Role::Ingest,
            RoleConfidence::Clear,
            format!("`{}` pulls in third-party content", tool.tool.name),
        );
    }
    if outbound_verb && (external_object || private_object) {
        tags.add(
            Role::Sink,
            RoleConfidence::Clear,
            format!("`{}` sends data outward", tool.tool.name),
        );
    }

    // --- description-driven tagging ---
    for (role, phrases, why) in [
        (
            Role::Source,
            SOURCE_PHRASES,
            "its description describes reading private state",
        ),
        (
            Role::Ingest,
            INGEST_PHRASES,
            "its description describes pulling in remote content",
        ),
        (
            Role::Sink,
            SINK_PHRASES,
            "its description describes sending data out",
        ),
    ] {
        if phrases.iter().any(|p| description.contains(p)) {
            tags.add(role, RoleConfidence::Clear, why);
        }
    }

    // --- capability-driven tagging ---
    //
    // Weaker evidence than the tool's own name, so tagged Ambiguous: a `file`
    // parameter can just as well name a remote document as a local one.
    for capability in capabilities {
        match capability {
            // A shell is both halves of an exfiltration on its own.
            Capability::CommandExecution | Capability::CodeEvaluation => {
                tags.add(
                    Role::Source,
                    RoleConfidence::Clear,
                    "it can execute code, which can read anything the server can",
                );
                tags.add(
                    Role::Sink,
                    RoleConfidence::Clear,
                    "it can execute code, which can send anything anywhere",
                );
            }
            Capability::FileAccess => tags.add(
                Role::Source,
                RoleConfidence::Ambiguous,
                "it takes a filesystem path, which may reach private files",
            ),
            Capability::NetworkAccess => {
                for (role, confidence, why) in network_direction(tool, &name_tokens, &description) {
                    tags.add(role, confidence, why);
                }
            }
            Capability::HeaderSmuggling => tags.add(
                Role::Sink,
                RoleConfidence::Ambiguous,
                "a parameter of it is copied into an outgoing HTTP header",
            ),
        }
    }

    tags.tags.sort_by_key(|t| t.role);
    tags
}

/// Decide which way a network tool moves data.
///
/// The hard case of the whole module: a URL parameter can mean a GET that pulls
/// content in (ingest) or a POST that pushes data out (sink), and plenty of
/// tools do both.
///
/// Resolution order: an explicit HTTP method in the schema, then the verb in
/// the tool's name, then the description. **When none of them settles it the
/// tool is tagged as both, Ambiguous** — a missed flow is a scanner that failed,
/// while an over-reported one is a chain someone has to look at for a minute.
/// The ambiguity is not hidden: it downgrades the finding from Critical to High
/// and is quoted in the message.
fn network_direction(
    tool: &ToolContext<'_>,
    name_tokens: &[String],
    description: &str,
) -> Vec<(Role, RoleConfidence, String)> {
    if let Some(method) = declared_http_method(tool) {
        if OUTBOUND_METHODS.contains(&method.as_str()) {
            return vec![(
                Role::Sink,
                RoleConfidence::Clear,
                format!("its schema declares the HTTP method `{method}`"),
            )];
        }
        if INBOUND_METHODS.contains(&method.as_str()) {
            return vec![(
                Role::Ingest,
                RoleConfidence::Clear,
                format!("its schema declares the HTTP method `{method}`"),
            )];
        }
    }

    let outbound = name_tokens
        .iter()
        .any(|t| OUTBOUND_VERBS.contains(&t.as_str()))
        || SINK_PHRASES.iter().any(|p| description.contains(p));
    let inbound = name_tokens
        .iter()
        .any(|t| INBOUND_VERBS.contains(&t.as_str()))
        || INGEST_PHRASES.iter().any(|p| description.contains(p));

    match (inbound, outbound) {
        (true, false) => vec![(
            Role::Ingest,
            RoleConfidence::Clear,
            "it takes a URL and its name reads as a retrieval".to_owned(),
        )],
        (false, true) => vec![(
            Role::Sink,
            RoleConfidence::Clear,
            "it takes a URL and its name reads as a send".to_owned(),
        )],
        // Ambiguous, or explicitly both: assume both, and say so.
        _ => vec![
            (
                Role::Ingest,
                RoleConfidence::Ambiguous,
                "it takes a URL and the direction could not be determined".to_owned(),
            ),
            (
                Role::Sink,
                RoleConfidence::Ambiguous,
                "it takes a URL and the direction could not be determined".to_owned(),
            ),
        ],
    }
}

/// An HTTP method fixed by the schema: a `method` parameter with a single-value
/// enum, or a default.
fn declared_http_method(tool: &ToolContext<'_>) -> Option<String> {
    let input_schema = tool.tool.input_schema.as_ref()?;
    for param in schema::flatten(input_schema).iter() {
        if !tokenize(&param.name).iter().any(|t| t == "method") {
            continue;
        }
        // Only a single allowed value settles the direction; an enum of
        // GET|POST means the tool does both.
        if param.enum_values.len() == 1 {
            return Some(param.enum_values[0].to_ascii_lowercase());
        }
    }
    None
}
