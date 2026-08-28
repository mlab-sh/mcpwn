//! The set of checks a scan runs.
//!
//! Adding a detection is one line in [`Registry::builtin`] and nothing else:
//! the analyzer never names a check, and no renderer knows any check exists.

use super::capabilities::CapabilityCheck;
use super::check::{GlobalCheck, ServerCheck, ToolCheck};
use super::config::{PinningCheck, SecretsCheck, TransportCheck};
use super::flow::ToxicFlowCheck;
use super::network::NetworkCheck;
use super::obfuscation::ObfuscationCheck;
use super::shadowing::ShadowingCheck;

/// The checks to run, split by the level they operate at.
#[derive(Debug, Default)]
pub struct Registry {
    tool_checks: Vec<Box<dyn ToolCheck>>,
    server_checks: Vec<Box<dyn ServerCheck>>,
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
            .with_tool_check(ObfuscationCheck::new())
            .with_server_check(SecretsCheck::new())
            .with_server_check(PinningCheck::new())
            .with_server_check(TransportCheck::new())
            .with_server_check(NetworkCheck::new())
            .with_global_check(ShadowingCheck::new())
            .with_global_check(ToxicFlowCheck::new())
    }

    pub fn with_server_check(mut self, check: impl ServerCheck + 'static) -> Self {
        self.server_checks.push(Box::new(check));
        self
    }

    pub fn server_checks(&self) -> impl Iterator<Item = &dyn ServerCheck> {
        self.server_checks.iter().map(AsRef::as_ref)
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
        self.tool_checks.len() + self.server_checks.len() + self.global_checks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
