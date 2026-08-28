//! The contract every security analyser implements.
//!
//! There are deliberately **two levels**, because the detections we know are
//! coming do not all look at the same thing:
//!
//! * [`ToolCheck`] sees one tool at a time. Most detections are of this shape,
//!   capabilities, obfuscation, poisoned descriptions.
//! * [`GlobalCheck`] sees every tool of every server at once. Toxic flows and
//!   shadowing only exist *between* tools, often across servers that each look
//!   harmless alone, so they cannot be expressed one tool at a time.
//!
//! Both receive the same [`ScanContext`], so a per-tool check can still look
//! around when it needs to without being promoted to a global one.

use crate::finding::Finding;
use crate::manifest::{ServerManifest, ToolManifest, ToolRef};
use crate::recon::ServerProbe;

/// Everything the analysers may look at: the whole scanned surface.
#[derive(Debug, Clone, Copy)]
pub struct ScanContext<'a> {
    servers: &'a [ServerManifest],
    /// What the optional `--probe` pass observed, keyed by endpoint URL. Empty
    /// unless probing was asked for, which is why every check that reads it
    /// must treat its absence as "not measured" rather than "nothing found".
    probes: &'a [ServerProbe],
}

impl<'a> ScanContext<'a> {
    pub fn new(servers: &'a [ServerManifest]) -> Self {
        Self {
            servers,
            probes: &[],
        }
    }

    pub fn with_probes(mut self, probes: &'a [ServerProbe]) -> Self {
        self.probes = probes;
        self
    }

    pub fn servers(&self) -> &'a [ServerManifest] {
        self.servers
    }

    /// The probe for a server, if one was taken.
    pub fn probe(&self, server: &ServerManifest) -> Option<&'a ServerProbe> {
        let url = match server.transport.as_ref()? {
            crate::manifest::Transport::Http { url } => url,
            _ => return None,
        };
        self.probes.iter().find(|p| &p.endpoint == url)
    }

    /// Every tool of every server, paired with the server it belongs to.
    pub fn tools(&self) -> impl Iterator<Item = ToolContext<'a>> {
        self.servers.iter().flat_map(|server| {
            server
                .tools
                .iter()
                .map(move |tool| ToolContext { server, tool })
        })
    }

    pub fn tool_count(&self) -> usize {
        self.servers.iter().map(|s| s.tools.len()).sum()
    }
}

/// One tool, and the server that advertises it.
#[derive(Debug, Clone, Copy)]
pub struct ToolContext<'a> {
    pub server: &'a ServerManifest,
    pub tool: &'a ToolManifest,
}

impl ToolContext<'_> {
    /// The stable reference carried by every [`Finding`] about this tool.
    pub fn tool_ref(&self) -> ToolRef {
        ToolRef::new(&self.server.name, &self.tool.name)
    }
}

/// A detection that examines one tool at a time.
pub trait ToolCheck: std::fmt::Debug + Send + Sync {
    /// Stable identifier, used in `--explain` and to disable a check later.
    fn id(&self) -> &'static str;

    /// One-line description of what this check looks for.
    fn description(&self) -> &'static str;

    fn check(&self, tool: &ToolContext<'_>, ctx: &ScanContext<'_>) -> Vec<Finding>;
}

/// A detection that examines one server: how it is launched, how it is reached,
/// what its configuration holds. It never looks at tools.
pub trait ServerCheck: std::fmt::Debug + Send + Sync {
    fn id(&self) -> &'static str;

    fn description(&self) -> &'static str;

    fn check(&self, server: &ServerManifest, ctx: &ScanContext<'_>) -> Vec<Finding>;
}

/// A detection that needs to see every tool at once.
///
/// Global checks run **after** every [`ToolCheck`], and receive what they
/// produced as `prior`. That ordering is a guarantee, not an accident: a global
/// check can build on per-tool conclusions instead of recomputing them; the
/// toxic-flow check reads the capabilities already found rather than
/// re-analysing every schema.
pub trait GlobalCheck: std::fmt::Debug + Send + Sync {
    fn id(&self) -> &'static str;

    fn description(&self) -> &'static str;

    fn check(&self, ctx: &ScanContext<'_>, prior: &[Finding]) -> Vec<Finding>;
}
