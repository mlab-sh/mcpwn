//! `mcp.lock`: the memory that makes rug-pull detection possible.
//!
//! Every other check answers "is this tool dangerous?" from one scan. Rug pull
//! asks "did this tool *change* since I approved it?", which needs a record of
//! what it looked like before. Mental model: `Cargo.lock`, for MCP tools.
//!
//! # Format
//!
//! JSON. The crate already depends on `serde_json` (so this costs nothing), it
//! is the format of every other mcpwn output, and; with servers sorted by id,
//! tools sorted by name and one field per line: it diffs cleanly in a code
//! review, which is the point of committing it.
//!
//! # Hashing raw content, on purpose
//!
//! The digest covers the **raw** text, with no Unicode normalisation. That is
//! deliberate and it is the opposite of what the semantic analysers do: adding
//! a zero-width character to a description *is* a mutation, and normalising
//! first would make exactly that attack invisible to this check. Normalisation
//! exists so a matcher cannot be evaded; the lock exists so a change cannot be
//! hidden. Different jobs, opposite treatment.
//!
//! # Canonical serialisation
//!
//! JSON is hashed through [`canonical`], which sorts object keys recursively
//! and emits no whitespace. Without it, a server that merely reformats its
//! schema would look like it mutated. This is written out by hand rather than
//! relying on `serde_json::Map` being a `BTreeMap`: that ordering is a *feature
//! flag* (`preserve_order`), and any dependency in the tree could flip it
//! through feature unification and silently change every hash.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::manifest::{ServerManifest, ToolManifest, Transport};

/// Format version. Bumped when the meaning of a field changes.
pub const LOCKFILE_VERSION: u32 = 1;

/// Default lockfile name, resolved in the working directory.
pub const DEFAULT_LOCK_FILE: &str = "mcp.lock";

// ---------------------------------------------------------------------------
// Server identity
// ---------------------------------------------------------------------------

/// A stable identifier for a server across scans.
///
/// This is the load-bearing design decision of the whole check: get it wrong
/// and either a renamed server looks like a new one (baseline lost), or two
/// different servers collide (mutations missed).
///
/// * **HTTP**: the endpoint URL, normalised: lowercase scheme and host,
///   default port dropped, trailing slash removed. The URL is what the client
///   actually talks to, and it survives the config being renamed or moved
///   between machines. Query strings are **kept**: they routinely carry a
///   tenant or an API version, so two URLs differing only there are two
///   different servers.
/// * **stdio**: the launch command and its arguments. The config key is a
///   user-chosen label that can be renamed at will; what identifies the server
///   is what gets executed.
/// * **neither**: falls back to the config-declared name, which is all there
///   is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerId(pub String);

impl ServerId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive the identity of a server from its manifest.
    pub fn from_manifest(server: &ServerManifest) -> Self {
        match server.transport.as_ref() {
            Some(Transport::Http { url }) => Self(normalize_url(url)),
            Some(Transport::Stdio { command, args, .. }) => {
                let mut id = format!("stdio:{command}");
                for arg in args {
                    id.push(' ');
                    id.push_str(arg);
                }
                Self(id)
            }
            Some(Transport::Unknown) | None => Self(format!("name:{}", server.name)),
        }
    }
}

impl std::fmt::Display for ServerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalise a URL so cosmetic differences do not split one server in two.
fn normalize_url(url: &str) -> String {
    let trimmed = url.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return trimmed.to_owned(),
    };

    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    let mut authority = authority.to_ascii_lowercase();

    // A default port is the same endpoint as no port at all.
    for (default, s) in [(":80", "http"), (":443", "https")] {
        if scheme == s {
            if let Some(stripped) = authority.strip_suffix(default) {
                authority = stripped.to_owned();
            }
        }
    }

    let tail = if tail == "/" { "" } else { tail };
    format!("{scheme}://{authority}{}", tail.trim_end_matches('/'))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Serialise JSON deterministically: keys sorted recursively, no whitespace.
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        // Delegated so escaping matches the JSON spec exactly.
        Value::String(s) => out.push_str(&Value::String(s.clone()).to_string()),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sorted explicitly: never rely on the map's own iteration order.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (key, value)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                write_canonical(value, out);
            }
            out.push('}');
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    // Hex-encoded by hand rather than through a formatting trait: the digest
    // output type has changed shape across RustCrypto releases, and a hash that
    // silently changes representation would invalidate every lockfile.
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest.iter() {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

/// The exact content covered by a tool's digest.
///
/// **name + description + inputSchema.** These three are what the model reads
/// and what decides whether it calls the tool and with what; a change to any
/// of them can change the agent's behaviour without the user seeing anything.
/// Everything else a server sends (`annotations`, `title`, vendor extensions)
/// is deliberately outside the digest for now: it is not yet acted upon, and
/// including it would produce mutation findings nobody can act on.
///
/// The tool `name` is part of the digest *and* the lookup key, so a renamed
/// tool appears as one removed and one added rather than as a mutation. That is
/// the honest reading: a different name is a different tool as far as the agent
/// is concerned.
pub fn digest_tool(tool: &ToolManifest) -> ToolDigest {
    let schema = tool.input_schema.clone().unwrap_or(Value::Null);
    let whole = serde_json::json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": schema,
    });

    ToolDigest {
        hash: sha256(canonical(&whole).as_bytes()),
        description: sha256(tool.description.as_bytes()),
        input_schema: sha256(canonical(&schema).as_bytes()),
    }
}

/// Per-tool digests: one overall, plus one per field so a diff can say *what*
/// changed rather than only *that* something did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDigest {
    pub hash: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: String,
}

// ---------------------------------------------------------------------------
// The lockfile
// ---------------------------------------------------------------------------

/// One tool as recorded in the lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedTool {
    pub name: String,
    #[serde(flatten)]
    pub digest: ToolDigest,
}

/// One server as recorded in the lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedServer {
    pub id: ServerId,
    /// When this server first entered the lock. Preserved across updates.
    #[serde(rename = "firstLocked")]
    pub first_locked: String,
    #[serde(rename = "lastUpdated")]
    pub last_updated: String,
    pub tools: Vec<LockedTool>,
}

impl LockedServer {
    fn tool(&self, name: &str) -> Option<&LockedTool> {
        self.tools.iter().find(|t| t.name == name)
    }
}

/// The lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    #[serde(rename = "lockfileVersion")]
    pub version: u32,
    pub generator: String,
    pub servers: Vec<LockedServer>,
}

impl Default for Lock {
    fn default() -> Self {
        Self {
            version: LOCKFILE_VERSION,
            generator: format!("{} {}", crate::NAME, crate::VERSION),
            servers: Vec::new(),
        }
    }
}

impl Lock {
    pub fn server(&self, id: &ServerId) -> Option<&LockedServer> {
        self.servers.iter().find(|s| &s.id == id)
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Read a lock from disk.
    ///
    /// A missing file is `Ok(None)`: it is the normal first-run state, not an
    /// error.
    pub fn load(path: &Path) -> crate::Result<Option<Self>> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        let lock: Self = serde_json::from_str(&raw).map_err(|err| {
            crate::Error::lock(
                path.display().to_string(),
                format!("not readable as a lockfile ({err})"),
            )
        })?;

        if lock.version != LOCKFILE_VERSION {
            return Err(crate::Error::lock(
                path.display().to_string(),
                format!(
                    "lockfile version {} is not supported (this build understands {LOCKFILE_VERSION})",
                    lock.version
                ),
            ));
        }
        Ok(Some(lock))
    }

    /// Write the lock, sorted for a readable diff.
    pub fn save(&self, path: &Path) -> crate::Result<()> {
        let mut lock = self.clone();
        lock.servers.sort_by(|a, b| a.id.cmp(&b.id));
        for server in &mut lock.servers {
            server.tools.sort_by(|a, b| a.name.cmp(&b.name));
        }
        let mut text = serde_json::to_string_pretty(&lock)?;
        text.push('\n');
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Produce an updated lock from what was just observed.
    ///
    /// `observed` holds **only servers that were actually enumerated**. A
    /// server that could not be reached keeps its existing entry untouched:
    /// otherwise one network failure plus `--update-lock` silently erases the
    /// baseline that makes the whole check work.
    pub fn updated_from(&self, observed: &[(ServerId, Vec<ToolManifest>)], now: &str) -> Self {
        let mut servers: Vec<LockedServer> = Vec::new();
        let seen: BTreeSet<&ServerId> = observed.iter().map(|(id, _)| id).collect();

        for (id, tools) in observed {
            let first_locked = self
                .server(id)
                .map(|s| s.first_locked.clone())
                .unwrap_or_else(|| now.to_owned());
            servers.push(LockedServer {
                id: id.clone(),
                first_locked,
                last_updated: now.to_owned(),
                tools: tools
                    .iter()
                    .map(|tool| LockedTool {
                        name: tool.name.clone(),
                        digest: digest_tool(tool),
                    })
                    .collect(),
            });
        }

        // Untouched servers survive verbatim.
        for existing in &self.servers {
            if !seen.contains(&existing.id) {
                servers.push(existing.clone());
            }
        }

        servers.sort_by(|a, b| a.id.cmp(&b.id));
        for server in &mut servers {
            server.tools.sort_by(|a, b| a.name.cmp(&b.name));
        }

        Self {
            version: LOCKFILE_VERSION,
            generator: format!("{} {}", crate::NAME, crate::VERSION),
            servers,
        }
    }

    /// Compare two recorded snapshots of the same server.
    ///
    /// Shared with [`Lock::compare`] so `mcpwn diff` and a scan can never
    /// disagree about what counts as a change.
    pub fn compare_locked(before: &LockedServer, after: &LockedServer) -> Vec<ToolChange> {
        let mut changes = Vec::new();

        for tool in &after.tools {
            match before.tool(&tool.name) {
                Some(previous) if previous.digest.hash != tool.digest.hash => {
                    let mut fields = Vec::new();
                    if previous.digest.description != tool.digest.description {
                        fields.push("description");
                    }
                    if previous.digest.input_schema != tool.digest.input_schema {
                        fields.push("inputSchema");
                    }
                    changes.push(ToolChange::Mutated {
                        name: tool.name.clone(),
                        fields,
                        was: previous.digest.hash.clone(),
                        now: tool.digest.hash.clone(),
                    });
                }
                Some(_) => {}
                None => changes.push(ToolChange::Added {
                    name: tool.name.clone(),
                }),
            }
        }
        for previous in &before.tools {
            if !after.tools.iter().any(|t| t.name == previous.name) {
                changes.push(ToolChange::Removed {
                    name: previous.name.clone(),
                });
            }
        }
        changes.sort_by(|a, b| a.name().cmp(b.name()));
        changes
    }

    /// Compare what was observed against the lock.
    ///
    /// Servers absent from the lock produce nothing: there is no baseline to
    /// compare against, and a first sighting is not a rug pull.
    pub fn compare(&self, id: &ServerId, tools: &[ToolManifest]) -> Vec<ToolChange> {
        let Some(locked) = self.server(id) else {
            return Vec::new();
        };
        let mut changes = Vec::new();

        for tool in tools {
            match locked.tool(&tool.name) {
                Some(previous) => {
                    let current = digest_tool(tool);
                    if current.hash != previous.digest.hash {
                        let mut fields = Vec::new();
                        if current.description != previous.digest.description {
                            fields.push("description");
                        }
                        if current.input_schema != previous.digest.input_schema {
                            fields.push("inputSchema");
                        }
                        changes.push(ToolChange::Mutated {
                            name: tool.name.clone(),
                            fields,
                            was: previous.digest.hash.clone(),
                            now: current.hash,
                        });
                    }
                }
                None => changes.push(ToolChange::Added {
                    name: tool.name.clone(),
                }),
            }
        }

        for previous in &locked.tools {
            if !tools.iter().any(|t| t.name == previous.name) {
                changes.push(ToolChange::Removed {
                    name: previous.name.clone(),
                });
            }
        }

        changes.sort_by(|a, b| a.name().cmp(b.name()));
        changes
    }
}

/// One difference between the lock and what a server now advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolChange {
    /// Same name, different content. The rug pull proper.
    Mutated {
        name: String,
        /// Which fields differ: `description`, `inputSchema`, or both.
        fields: Vec<&'static str>,
        was: String,
        now: String,
    },
    /// In the lock, no longer advertised.
    Removed { name: String },
    /// Advertised, never locked, so never reviewed.
    Added { name: String },
}

impl ToolChange {
    pub fn name(&self) -> &str {
        match self {
            ToolChange::Mutated { name, .. }
            | ToolChange::Removed { name }
            | ToolChange::Added { name } => name,
        }
    }
}

/// ISO-8601 UTC timestamp for `now`, without pulling in a date library.
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso8601(secs)
}

/// Format a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Howard Hinnant's civil-from-days algorithm; a lockfile meant to be read in a
/// diff deserves a readable date, and this is cheaper than a date dependency.
pub fn iso8601(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}
