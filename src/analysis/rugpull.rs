//! Rug-pull analysis: did a tool change after it was approved?
//!
//! A [`GlobalCheck`] rather than a per-tool one, because the question is asked
//! per *server*: whether a tool is missing is only answerable by looking at the
//! whole server's tool list at once.
//!
//! # Detection never writes
//!
//! This check only reads the lock. Rewriting it is a separate, explicit action
//! (`--update-lock`), and that separation is the check: a scan that refreshed
//! the baseline as it went would erase the very mutation it just found, and the
//! second run would come back clean. Detection and blessing are different acts.

use std::collections::BTreeSet;

use crate::analysis::check::{GlobalCheck, ScanContext};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::lock::{Lock, ServerId, ToolChange};
use crate::manifest::ToolRef;

/// Compares the current scan against a lockfile.
#[derive(Debug, Clone)]
pub struct RugPullCheck {
    lock: Lock,
    /// Servers whose tools were actually observed this run.
    ///
    /// A server that failed to enumerate has an empty tool list, which is
    /// indistinguishable from "every tool was removed" unless we are told. One
    /// unreachable endpoint must not produce a wall of removal findings.
    observed: BTreeSet<ServerId>,
}

impl RugPullCheck {
    pub fn new(lock: Lock, observed: BTreeSet<ServerId>) -> Self {
        Self { lock, observed }
    }
}

impl GlobalCheck for RugPullCheck {
    fn id(&self) -> &'static str {
        "rug-pull"
    }

    fn description(&self) -> &'static str {
        "Compares each tool against the mcp.lock baseline and reports what changed."
    }

    fn check(&self, ctx: &ScanContext<'_>, _prior: &[Finding]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in ctx.servers() {
            let id = ServerId::from_manifest(server);
            if !self.observed.contains(&id) {
                continue; // not enumerated this run: nothing to compare.
            }
            if self.lock.server(&id).is_none() {
                continue; // no baseline: a first sighting is not a rug pull.
            }

            for change in self.lock.compare(&id, &server.tools) {
                findings.push(finding(&server.name, &id, &change));
            }
        }

        findings
    }
}

fn finding(server_name: &str, id: &ServerId, change: &ToolChange) -> Finding {
    let subject = ToolRef::new(server_name, change.name());

    match change {
        ToolChange::Mutated {
            name,
            fields,
            was,
            now,
        } => {
            let what = if fields.is_empty() {
                "its content".to_owned()
            } else {
                fields
                    .iter()
                    .map(|f| format!("`{f}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            };
            Finding::builder(
                "MCPWN-RUG-001",
                Category::RugPull,
                Severity::High,
                format!("Tool changed since it was locked: `{name}`"),
            )
            .message(format!(
                "`{name}` on `{id}` no longer matches the lockfile: {what} changed. The tool the \
                 agent will now be shown is not the one that was reviewed. Nothing here says the \
                 change is hostile: it says it happened without being approved."
            ))
            .confidence(Confidence::High)
            .subject(subject)
            .remediation(
                "Diff the current description and schema against what you approved. If the change \
                 is legitimate, re-lock with --update-lock.",
            )
            .evidence(Evidence::new("locked digest", was.clone()))
            .evidence(Evidence::new("current digest", now.clone()))
            .build()
        }

        ToolChange::Removed { name } => Finding::builder(
            "MCPWN-RUG-002",
            Category::RugPull,
            Severity::Info,
            format!("Tool in the lockfile is no longer advertised: `{name}`"),
        )
        .message(format!(
            "`{name}` is recorded in the lockfile for `{id}` but the server no longer advertises \
             it. Usually a deliberate removal; worth a glance if you did not expect it."
        ))
        .confidence(Confidence::High)
        .subject(subject)
        .remediation("Confirm the removal was intended, then re-lock with --update-lock.")
        .build(),

        ToolChange::Added { name } => Finding::builder(
            "MCPWN-RUG-003",
            Category::RugPull,
            Severity::Info,
            format!("Tool not in the lockfile: `{name}`"),
        )
        .message(format!(
            "`{name}` is advertised by `{id}` but is absent from the lockfile, so it has never \
             been reviewed. A server quietly gaining a tool is how new capability arrives without \
             anyone deciding to grant it."
        ))
        .confidence(Confidence::High)
        .subject(subject)
        .remediation("Review the new tool, then re-lock with --update-lock.")
        .build(),
    }
}
