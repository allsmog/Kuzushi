//! Engagement scope: the authorization boundary every live play must clear.
//!
//! An [`EngagementScope`] is what an operator declares before any active
//! target operation — the allowlist of hosts/CIDRs/domains in scope, optional
//! exclusions and a time window, and an explicit authorization marker. The
//! gate is **refuse-by-default**: an empty or unauthorized scope denies every
//! target, so a live play can never fire without the operator having put the
//! target in scope on purpose. Loadable from `.kuzushi/engagement-scope.json`.
//!
//! The decision is a pure function of `(scope, target, now)` — no clock, no
//! DNS, no network — so it is fully testable and the same verdict is
//! reproducible in an audit trail.

mod entry;
mod target;
mod window;

pub use entry::ScopeEntry;
pub use target::ScopeTarget;
pub use window::ScopeWindow;

use serde::{Deserialize, Serialize};

/// An operator-declared authorization boundary for live target operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EngagementScope {
    /// Must be explicitly true. A scope that is not marked authorized denies
    /// every target — declaring hosts in scope is not the same as asserting
    /// you are allowed to test them.
    #[serde(default)]
    pub authorized: bool,
    /// Free-text authorization reference (engagement id, `HTB:boxname`,
    /// `lab`). Recorded with every decision for the audit trail; required to
    /// be non-empty when `authorized` is true.
    #[serde(default)]
    pub authorization_ref: String,
    /// Targets that are in scope. Empty means nothing is in scope.
    #[serde(default)]
    pub in_scope: Vec<ScopeEntry>,
    /// Carve-outs that override `in_scope` (a host inside an in-scope CIDR
    /// the client excluded). Exclusions always win.
    #[serde(default)]
    pub exclusions: Vec<ScopeEntry>,
    /// Optional engagement time window. Outside it, every target is denied.
    #[serde(default)]
    pub window: Option<ScopeWindow>,
}

/// The verdict for one target. `Denied` always carries a reason so the
/// operator (and the audit log) sees why a play was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    Allowed,
    Denied(String),
}

impl ScopeDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ScopeDecision::Allowed)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            ScopeDecision::Allowed => None,
            ScopeDecision::Denied(reason) => Some(reason),
        }
    }
}

impl EngagementScope {
    /// Decide whether `target` may be operated against at `now_unix`.
    /// Refuse-by-default: authorization, time window, exclusions, and the
    /// allowlist are checked in that order, and the first failing gate wins.
    pub fn decide(&self, target: &ScopeTarget, now_unix: u64) -> ScopeDecision {
        if let Some(denied) = self.authorization_denial() {
            return denied;
        }
        if let Some(denied) = self.window_denial(now_unix) {
            return denied;
        }
        self.membership_decision(target)
    }

    /// Exclusions win over the allowlist; an unmatched target is denied.
    fn membership_decision(&self, target: &ScopeTarget) -> ScopeDecision {
        if self.exclusions.iter().any(|entry| entry.matches(target)) {
            return ScopeDecision::Denied(format!("{target} is explicitly excluded from scope"));
        }
        if self.in_scope.iter().any(|entry| entry.matches(target)) {
            return ScopeDecision::Allowed;
        }
        ScopeDecision::Denied(format!("{target} is not in the declared engagement scope"))
    }

    fn authorization_denial(&self) -> Option<ScopeDecision> {
        if !self.authorized {
            return Some(ScopeDecision::Denied(
                "engagement scope is not marked authorized".to_string(),
            ));
        }
        if self.authorization_ref.trim().is_empty() {
            return Some(ScopeDecision::Denied(
                "authorized scope requires an authorizationRef (engagement id, HTB:box, lab)"
                    .to_string(),
            ));
        }
        None
    }

    fn window_denial(&self, now_unix: u64) -> Option<ScopeDecision> {
        let window = self.window.as_ref()?;
        window
            .contains(now_unix)
            .then_some(())
            .map_or_else(|| Some(ScopeDecision::Denied(window.denial_reason())), |()| None)
    }
}

#[cfg(test)]
mod tests;
