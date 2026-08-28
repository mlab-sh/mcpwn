//! The public entry point of the engine.
//!
//! Feed it [`ServerManifest`]s, get a [`Report`] back. It owns the order in
//! which the detection modules run and is the only place that knows they exist;
//! callers never invoke a module directly.

use crate::analysis::{flow, roles, rules, schema};
use crate::manifest::ServerManifest;
use crate::report::{Report, ScanMeta};

/// Knobs that change what the engine reports.
#[derive(Debug, Clone, Default)]
pub struct AnalyzerConfig {
    /// What was scanned, recorded in the report metadata.
    pub target: Option<String>,
    /// Skip cross-server toxic-flow analysis (single-server scans).
    pub skip_flow: bool,
}

/// The analysis engine. Cheap to build, reusable across scans.
#[derive(Debug)]
pub struct Analyzer {
    config: AnalyzerConfig,
    rules: rules::RuleSet,
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
            rules: rules::RuleSet::builtin(),
        }
    }

    /// Replace the built-in rule set.
    pub fn with_rules(mut self, rules: rules::RuleSet) -> Self {
        self.rules = rules;
        self
    }

    /// Run every detection module over the given servers.
    ///
    /// The modules are all stubs today, so the report comes back with accurate
    /// metadata and no findings — the wiring is real, the detection is not.
    pub fn analyze(&self, servers: &[ServerManifest]) -> Report {
        let mut meta = ScanMeta::new(self.config.target.clone());
        meta.servers = servers.len();
        meta.tools = servers.iter().map(|s| s.tools.len()).sum();

        let mut report = Report::new(meta);

        // Per-tool passes.
        for server in servers {
            for tool in &server.tools {
                // Role tagging feeds the flow graph; kept here so a future
                // flow pass reuses it instead of recomputing.
                let _tags = roles::tag_tool(server, tool);

                report.extend(self.rules.match_tool(server, tool));
                report.extend(schema::analyze_tool(server, tool));
            }
        }

        // Cross-server pass.
        if !self.config.skip_flow {
            report.extend(flow::analyze(servers));
        }

        report.sort();
        report
    }
}
