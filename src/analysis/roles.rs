//! Tagging each tool with the roles it can play in a data-exfiltration chain.
//!
//! * **Source**  — can read sensitive local state (files, secrets, history).
//! * **Ingest**  — pulls in attacker-controlled content (web, issues, mail).
//! * **Sink**    — can send data outward (HTTP, mail, git push, shell).
//!
//! A single tool can carry several roles; a tool that is source + sink is a
//! one-hop toxic flow on its own.
//!
//! Not implemented yet.

use serde::{Deserialize, Serialize};

use crate::manifest::{ServerManifest, ToolManifest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Role {
    Source,
    Ingest,
    Sink,
}

impl Role {
    pub fn slug(self) -> &'static str {
        match self {
            Role::Source => "source",
            Role::Ingest => "ingest",
            Role::Sink => "sink",
        }
    }

    pub const ALL: [Role; 3] = [Role::Source, Role::Ingest, Role::Sink];
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// The roles inferred for one tool, plus why.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTags {
    #[serde(default)]
    pub roles: Vec<Role>,
    /// Human-readable justification per role, e.g. "reads `path` from disk".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rationale: Vec<String>,
}

impl RoleTags {
    pub fn has(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }
}

/// Infer the roles of a single tool from its name, description and schema.
///
/// Returns no roles until the heuristics land.
pub fn tag_tool(_server: &ServerManifest, _tool: &ToolManifest) -> RoleTags {
    RoleTags::default()
}
