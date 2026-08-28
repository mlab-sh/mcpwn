//! The set of checks a scan runs.
//!
//! Adding a detection is one line in [`Registry::builtin`] and nothing else:
//! the analyzer never names a check, and no renderer knows any check exists.

use super::capabilities::CapabilityCheck;
use super::check::{GlobalCheck, ToolCheck};
use super::flow::ToxicFlowCheck;

/// The checks to run, split by the level they operate at.
#[derive(Debug, Default)]
pub struct Registry {
    tool_checks: Vec<Box<dyn ToolCheck>>,
    global_checks: Vec<Box<dyn GlobalCheck>>,
}

impl Registry {
    /// No checks at all. Useful for tests that want one check in isolation.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every check shipped with mcpwn.
    ///
    /// **This is the list.** Register a new detection here.
    pub fn builtin() -> Self {
        Self::empty()
            .with_tool_check(CapabilityCheck::new())
            .with_global_check(ToxicFlowCheck::new())
    }

    pub fn with_tool_check(mut self, check: impl ToolCheck + 'static) -> Self {
        self.tool_checks.push(Box::new(check));
        self
    }

    pub fn with_global_check(mut self, check: impl GlobalCheck + 'static) -> Self {
        self.global_checks.push(Box::new(check));
        self
    }

    pub fn tool_checks(&self) -> impl Iterator<Item = &dyn ToolCheck> {
        self.tool_checks.iter().map(AsRef::as_ref)
    }

    pub fn global_checks(&self) -> impl Iterator<Item = &dyn GlobalCheck> {
        self.global_checks.iter().map(AsRef::as_ref)
    }

    pub fn len(&self) -> usize {
        self.tool_checks.len() + self.global_checks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
