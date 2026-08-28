//! Terminal-facing projection of one recorded proof deferral.
//!
//! Every surface that can show a deferred finding — the shell Prove page, its
//! plain output, and `kuzushi finding` — renders this one projection, so the
//! operator's decision reads the same everywhere. The projection deliberately
//! carries no proof state: a deferral says work was postponed, not that any
//! evidence exists.

use super::{ProofDeferralActor, ProofDeferralRecorded};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofDeferralView {
    /// Durable identity when the finding has one, else its fingerprint.
    pub subject: String,
    pub fingerprint: String,
    pub identity_id: Option<String>,
    /// The exact discovery generation the deferral is bound to.
    pub scan_id: String,
    pub reason: String,
    pub actor: &'static str,
    pub recorded_at_unix: u64,
}

impl ProofDeferralView {
    pub fn from_record(record: &ProofDeferralRecorded) -> Self {
        Self {
            subject: record
                .identity_id
                .clone()
                .unwrap_or_else(|| record.finding_fingerprint.clone()),
            fingerprint: record.finding_fingerprint.clone(),
            identity_id: record.identity_id.clone(),
            scan_id: record.finding_scan_id.clone(),
            reason: record.reason.clone(),
            actor: record.actor.as_str(),
            recorded_at_unix: record.recorded_at_unix,
        }
    }

    /// The one-line disclosure shared by the Prove page, plain output, and the
    /// headless finding detail. It names the decision, its author, and the
    /// generation it is bound to — never a proof state.
    pub fn disclosure_line(&self) -> String {
        format!(
            "proof deferred by {} at generation {} · {}",
            self.actor, self.scan_id, self.reason
        )
    }
}

impl ProofDeferralActor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "operator",
        }
    }
}
