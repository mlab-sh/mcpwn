//! `mcpwn.toml`: the file that makes the scanner survivable in CI.
//!
//! A scanner with no way to say "yes, we know, it is intentional" gets one of
//! two fates: it is muted entirely, or its output is skimmed and ignored. The
//! policy file is what lets a team keep the signal by writing down the noise,
//! and, crucially, *why* each exception exists, so the list can be reviewed
//! instead of accumulating forever.
//!
//! TOML rather than JSON here, unlike the lockfile: this one is written by
//! hand, and comments matter for exactly the reason above.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::finding::Severity;
use crate::report::Report;

/// Default policy file name, resolved in the working directory.
pub const DEFAULT_POLICY_FILE: &str = "mcpwn.toml";

/// What to do with a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetting {
    /// Drop every finding of this rule.
    Off,
    /// Report it at this severity instead of its own.
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RuleSetting {
    fn severity(self) -> Option<Severity> {
        match self {
            RuleSetting::Off => None,
            RuleSetting::Critical => Some(Severity::Critical),
            RuleSetting::High => Some(Severity::High),
            RuleSetting::Medium => Some(Severity::Medium),
            RuleSetting::Low => Some(Severity::Low),
            RuleSetting::Info => Some(Severity::Info),
        }
    }
}

/// One accepted finding.
///
/// `reason` is required on purpose. A suppression without a stated reason is
/// indistinguishable from one added to make a build go green, and nobody can
/// review it later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    /// Rule id, e.g. `MCPWN-CAP-001`.
    pub rule: String,
    /// Scope it applies to: `server::tool`, or a bare server name. Omitted
    /// means every finding of that rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Why this is accepted.
    pub reason: String,
}

/// The policy file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Lowest severity that makes the scan exit non-zero.
    #[serde(default, rename = "fail-on")]
    pub fail_on: Option<Severity>,
    /// Per-rule overrides: `"MCPWN-CAP-003" = "medium"` or `= "off"`.
    #[serde(default)]
    pub rules: BTreeMap<String, RuleSetting>,
    /// Accepted findings.
    #[serde(default)]
    pub ignore: Vec<Suppression>,
}

/// What a policy did to a report, so the run can say so out loud.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyEffect {
    pub disabled: usize,
    pub suppressed: usize,
    pub retuned: usize,
}

impl PolicyEffect {
    pub fn is_empty(&self) -> bool {
        self.disabled == 0 && self.suppressed == 0 && self.retuned == 0
    }
}

impl Policy {
    /// Read a policy file. A missing file is `Ok(None)`, the normal state.
    pub fn load(path: &Path) -> crate::Result<Option<Self>> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let policy: Self = toml::from_str(&raw).map_err(|err| {
            crate::Error::policy(path.display().to_string(), err.message().to_owned())
        })?;
        policy.validate(path)?;
        Ok(Some(policy))
    }

    fn validate(&self, path: &Path) -> crate::Result<()> {
        for id in self.rules.keys() {
            if crate::explain::lookup(id).is_none() {
                return Err(crate::Error::policy(
                    path.display().to_string(),
                    format!(
                        "`{id}` is not a rule mcpwn can emit; run `mcpwn explain` for the list"
                    ),
                ));
            }
        }
        for suppression in &self.ignore {
            if crate::explain::lookup(&suppression.rule).is_none() {
                return Err(crate::Error::policy(
                    path.display().to_string(),
                    format!(
                        "`{}` is not a rule mcpwn can emit; run `mcpwn explain` for the list",
                        suppression.rule
                    ),
                ));
            }
            if suppression.reason.trim().is_empty() {
                return Err(crate::Error::policy(
                    path.display().to_string(),
                    format!("the suppression for `{}` has no reason", suppression.rule),
                ));
            }
        }
        Ok(())
    }

    /// Apply the policy to a report, in place.
    pub fn apply(&self, report: &mut Report) -> PolicyEffect {
        let mut effect = PolicyEffect::default();

        report.findings.retain_mut(|finding| {
            let id = finding.id.as_str().to_owned();

            if let Some(setting) = self.rules.get(&id) {
                match setting.severity() {
                    None => {
                        effect.disabled += 1;
                        return false;
                    }
                    Some(severity) if severity != finding.severity => {
                        finding.severity = severity;
                        effect.retuned += 1;
                    }
                    Some(_) => {}
                }
            }

            let scope = finding.scope();
            let suppressed = self.ignore.iter().any(|s| {
                s.rule.eq_ignore_ascii_case(&id)
                    && match (&s.scope, &scope) {
                        (None, _) => true,
                        (Some(wanted), Some(actual)) => wanted == actual,
                        (Some(_), None) => false,
                    }
            });
            if suppressed {
                effect.suppressed += 1;
                return false;
            }
            true
        });

        report.sort();
        effect
    }

    /// The severity at or above which a scan should fail.
    pub fn fail_on(&self) -> Severity {
        // Info findings (a new tool, a removed tool) are notes, not failures.
        // Failing on them would train everyone to pass `--fail-on` blindly.
        self.fail_on.unwrap_or(Severity::Low)
    }
}

/// A starter policy file, printed by `mcpwn init-policy`.
pub const TEMPLATE: &str = r#"# mcpwn policy.
#
# `mcpwn scan` reads this file from the working directory unless --policy says
# otherwise. Run `mcpwn explain` to list every rule id.

# Lowest severity that makes the scan exit non-zero. Default: "low", so
# informational findings (a new tool, a removed tool) do not fail a build.
fail-on = "low"

# Per-rule overrides. "off" drops the rule entirely; a severity re-tunes it.
[rules]
# "MCPWN-CAP-003" = "medium"   # filesystem access is expected in this repo
# "MCPWN-RUG-003" = "off"      # we add tools often and review them elsewhere

# Accepted findings. `reason` is required: a suppression nobody can review is
# indistinguishable from one added to make the build go green.
# [[ignore]]
# rule = "MCPWN-CAP-001"
# scope = "shell::run_command"   # server::tool, or a bare server name
# reason = "reviewed 2026-08; this server exists to run commands"
"#;
