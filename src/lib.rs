//! **mcpwn** — a static, offline security scanner for MCP (Model Context
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
pub mod error;
pub mod finding;
pub mod manifest;
pub mod output;
pub mod report;

pub use analyzer::{Analyzer, AnalyzerConfig};
pub use error::{Error, Result};
pub use finding::{Category, Confidence, Evidence, Finding, FindingId, Severity, Span};
pub use manifest::{ServerManifest, ToolManifest, ToolRef};
pub use report::{Report, ScanMeta};

/// Version of the scanner, stamped into every report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical tool name, used in SARIF and `--version` output.
pub const NAME: &str = "mcpwn";
