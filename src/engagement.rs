//! The engagement file: the only way into `mcpwn audit`.
//!
//! Everything else in mcpwn reads. The audit binary *calls tools*, which means
//! it acts on the target: it creates, sends, writes and spends whatever the
//! tools it is allowed to call create, send, write and spend. Pointing that at
//! somebody else's server is not scanning, it is using their infrastructure.
//!
//! So there is no `--url`. There is no config discovery, which would let one
//! command reach every server on a machine. There is one file, naming one
//! target, the tools that may be called on it, and who authorised it. The file
//! is the artefact: a flag anyone can type is not a record of anything.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Default engagement file name.
pub const DEFAULT_ENGAGEMENT_FILE: &str = "engagement.toml";

/// Where the audit is pointed, and what it may do there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engagement {
    /// The one target. An `https://` endpoint, or `stdio:` followed by the
    /// command to launch.
    pub target: String,
    /// Who authorised this. Recorded in the transcript.
    pub authorized_by: String,
    /// Engagement or ticket reference, recorded in the transcript.
    #[serde(default)]
    pub reference: Option<String>,
    /// Arguments for a `stdio:` target, if it needs any.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment for a `stdio:` target.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Extra HTTP headers for an endpoint target.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub tools: Tools,
    #[serde(default)]
    pub callback: Option<String>,
}

/// Bounds on what the run may do, so an audit cannot become an outage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Requests per second. Deliberately slow by default.
    #[serde(default = "default_rate")]
    pub rate_per_second: f64,
    /// Hard ceiling on tool calls for the whole run.
    #[serde(default = "default_max_requests")]
    pub max_requests: usize,
    /// Seconds any one call may take.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_rate() -> f64 {
    2.0
}
fn default_max_requests() -> usize {
    500
}
fn default_timeout() -> u64 {
    20
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rate_per_second: default_rate(),
            max_requests: default_max_requests(),
            timeout_seconds: default_timeout(),
        }
    }
}

/// What may be called, and what may be run against it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tools {
    /// Tools that may be called. **Empty means nothing is called**, which is
    /// the default: a tool has to be named before it is touched.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Probes that may run. Empty means all of the non-dangerous ones.
    #[serde(default)]
    pub probes: Vec<String>,
    /// Permit calling tools that the static analysis flagged as a sink or as
    /// command execution. Off by default: fuzzing `send_email` sends email.
    #[serde(default)]
    pub allow_dangerous: bool,
}

impl Engagement {
    pub fn load(path: &Path) -> crate::Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|err| {
            crate::Error::engagement(
                path.display().to_string(),
                format!("cannot be read ({err})"),
            )
        })?;
        let engagement: Self = toml::from_str(&raw).map_err(|err| {
            crate::Error::engagement(path.display().to_string(), err.message().to_owned())
        })?;
        engagement.validate(path)?;
        Ok(engagement)
    }

    fn validate(&self, path: &Path) -> crate::Result<()> {
        let bad = |message: String| crate::Error::engagement(path.display().to_string(), message);

        if self.authorized_by.trim().is_empty() {
            return Err(bad(
                "`authorized_by` is empty. This file is the record that \
                            somebody signed off on running this; an unsigned one is worth \
                            nothing."
                    .to_owned(),
            ));
        }
        if self.target.trim().is_empty() {
            return Err(bad("`target` is empty".to_owned()));
        }
        if !self.is_stdio() && crate::enumerate::validate_endpoint(&self.target).is_err() {
            return Err(bad(format!(
                "`{}` is neither an http(s) URL nor a `stdio:` command",
                self.target
            )));
        }
        if self.tools.allow.is_empty() {
            return Err(bad(
                "`tools.allow` is empty, so nothing would be called. Name the \
                            tools this engagement covers."
                    .to_owned(),
            ));
        }
        if self.limits.rate_per_second <= 0.0 || self.limits.rate_per_second > 50.0 {
            return Err(bad(
                "`limits.rate_per_second` must be between 0 and 50".to_owned()
            ));
        }
        if self.limits.max_requests == 0 || self.limits.max_requests > 20_000 {
            return Err(bad(
                "`limits.max_requests` must be between 1 and 20000".to_owned()
            ));
        }
        Ok(())
    }

    /// Whether the target is a local process rather than an endpoint.
    pub fn is_stdio(&self) -> bool {
        self.target.starts_with("stdio:")
    }

    /// The command for a `stdio:` target.
    pub fn command(&self) -> Option<&str> {
        self.target.strip_prefix("stdio:").map(str::trim)
    }

    pub fn allows_tool(&self, name: &str) -> bool {
        self.tools.allow.iter().any(|t| t == name)
    }

    pub fn allowed_probes(&self) -> Option<BTreeSet<&str>> {
        if self.tools.probes.is_empty() {
            None // no list means every probe that is not gated
        } else {
            Some(self.tools.probes.iter().map(String::as_str).collect())
        }
    }
}

/// A starter engagement file, printed by `mcpwn audit init`.
pub const TEMPLATE: &str = r#"# mcpwn audit engagement.
#
# For educational and authorised use only. Running this calls tools on the
# target, which acts on it. Point it only at systems you own or have written
# permission to assess.
#
# This file is the only way to run an audit. It names one target, the tools that
# may be called on it, and who authorised it. There is no --url and no config
# discovery: one command must never be able to reach every server on a machine.
#
# Running this calls tools on the target. Tools do things. Do not point it at
# anything you are not entitled to act on.

target = "https://mcp.example.com/mcp"
authorized_by = "you@example.com"
reference = "PT-2026-000"

# For a local server instead:
# target = "stdio:npx"
# args = ["-y", "@vendor/mcp-server@1.2.3"]
# env = { API_TOKEN = "..." }

# For an endpoint that needs credentials:
# headers = ["Authorization: Bearer ..."]

[limits]
rate_per_second = 2      # deliberately slow
max_requests = 500       # hard ceiling for the whole run
timeout_seconds = 20

[tools]
# Nothing is called unless it is named here. This list is the scope.
allow = ["read_file", "fetch_url"]

# Probes to run. Omit for all of the ungated ones.
# probes = ["path-traversal", "ssrf", "command-injection", "sql-injection"]

# Permit calling tools the static analysis flagged as a sink or as command
# execution. Off by default, because fuzzing `send_email` sends email.
allow_dangerous = false

# A URL the target should be able to reach, for the out-of-band SSRF probe.
# Without one, only the in-band probes run.
# callback = "https://your-collaborator.example/mcpwn"
"#;
