//! **mcpwn**: a static, offline security scanner for MCP (Model Context
//! Protocol) servers.
//!
//! The engine never launches an MCP server, never connects to one and never
//! sends anything over the network: it reads manifests and reasons about them.
//!
//! ```no_run
//! use mcpwn::{Analyzer, ServerManifest};
//!
//! let servers: Vec<ServerManifest> = Vec::new();
//! let report = Analyzer::new().analyze(&servers);
//! assert!(report.is_empty());
//! ```

#![warn(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod analysis;
pub mod analyzer;
pub mod discovery;
pub mod enumerate;
pub mod error;
pub mod explain;
pub mod finding;
pub mod loading;
pub mod lock;
pub mod manifest;
pub mod output;
pub mod policy;
pub mod recon;
pub mod report;

pub use analysis::capabilities::{Capability, CapabilityCheck};
pub use analysis::check::{GlobalCheck, ScanContext, ServerCheck, ToolCheck, ToolContext};
pub use analysis::config::{PinningCheck, SecretsCheck, TransportCheck};
pub use analysis::network::NetworkCheck;
pub use analysis::normalize::{normalize, Normalized, NoteKind};
pub use analysis::obfuscation::ObfuscationCheck;
pub use analysis::registry::Registry;
pub use analysis::rugpull::RugPullCheck;
pub use analysis::shadowing::ShadowingCheck;
pub use analyzer::{Analyzer, AnalyzerConfig};
pub use discovery::{Client, ConfigFormat, DiscoveredConfig, Scope};
pub use enumerate::{EnumeratedServer, Enumeration, StaticEnumerator};
pub use error::{Error, Result};
pub use explain::RuleDoc;
pub use finding::{Category, Confidence, Evidence, Finding, FindingId, Severity, Span};
pub use loading::{LoadStatus, LoadedConfig};
pub use lock::{Lock, LockedServer, LockedTool, ServerId, ToolChange};
pub use manifest::{ServerManifest, ToolManifest, ToolRef, Transport};
pub use policy::Policy;
pub use recon::{Prober, ServerProbe};
pub use report::{Report, ScanMeta};

/// Version of the scanner, stamped into every report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical tool name, used in SARIF and `--version` output.
pub const NAME: &str = "mcpwn";
