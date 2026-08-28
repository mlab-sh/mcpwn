//! The public entry point of the engine.
//!
//! Feed it [`ServerManifest`]s, get a [`Report`] back. It owns the *pipeline* —
//! the order checks run in and how their findings are aggregated — but knows
//! nothing about any individual check: that list lives in
//! [`Registry::builtin`].

use crate::analysis::check::ScanContext;
use crate::analysis::registry::Registry;
use crate::manifest::ServerManifest;
use crate::report::{Report, ScanMeta};

/// Knobs that change what the engine reports.
#[derive(Debug, Clone, Default)]
pub struct AnalyzerConfig {
    /// What was scanned, recorded in the report metadata.
    pub target: Option<String>,
    /// Skip the checks that need to see every server at once.
    pub skip_global: bool,
}

/// The analysis engine. Cheap to build, reusable across scans.
#[derive(Debug)]
pub struct Analyzer {
    config: AnalyzerConfig,
    registry: Registry,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer {
    pub fn new() -> Self {
        Self::with_config(AnalyzerConfig::default())
    }

    pub fn with_config(config: AnalyzerConfig) -> Self {
        Self {
            config,
            registry: Registry::builtin(),
        }
    }

    /// Replace the check set — used by tests to exercise one check alone.
    pub fn with_registry(mut self, registry: Registry) -> Self {
        self.registry = registry;
        self
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Run every registered check over the given servers.
    ///
    /// Per-tool checks run first, then the global ones, so a future global
    /// check could in principle consider what the per-tool pass produced. Every
    /// finding lands in the same [`Report`], sorted most severe first.
    pub fn analyze(&self, servers: &[ServerManifest]) -> Report {
        let ctx = ScanContext::new(servers);

        let mut meta = ScanMeta::new(self.config.target.clone());
        meta.servers = servers.len();
        meta.tools = ctx.tool_count();
        let mut report = Report::new(meta);

        for tool in ctx.tools() {
            for check in self.registry.tool_checks() {
                report.extend(check.check(&tool, &ctx));
            }
        }

        if !self.config.skip_global {
            for check in self.registry.global_checks() {
                report.extend(check.check(&ctx));
            }
        }

        report.sort();
        report
    }
}
