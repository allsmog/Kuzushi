use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod confidence_band;
mod extract_cwe;
mod finding_identity;
mod finding_record;
mod from_semgrep;
mod now_isoish;
mod patch_status;
mod persisted_results;
mod proof_confidence;
mod review_decision;
mod static_proof_state;
mod triage_outcome;
mod triage_state;

pub use confidence_band::ConfidenceBand;
pub use extract_cwe::extract_cwe;
pub(crate) use finding_identity::finding_identity_key_for_finding;
pub use finding_identity::{
    compute_finding_identity_id, finding_identity_alias, FindingIdentityMatchTier,
};
pub use finding_record::{
    compute_dedup_key, compute_root_cause_key, compute_source_signature, normalize_cwe, Finding,
    FindingEvidence, FindingSource,
};
pub use from_semgrep::{Severity, VulnSource};
pub(crate) use now_isoish::now_isoish;
pub use patch_status::PatchStatus;
pub use persisted_results::{
    PatchAttempt, PatchResult, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, TriageAuthor, TriageVerdict,
};
pub use proof_confidence::ProofConfidence;
pub use review_decision::{
    DismissReason, ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict,
};
pub(crate) use static_proof_state::is_runtime_proof_state;
pub use static_proof_state::{StaticProofState, StaticProofStateEvent};
pub use triage_outcome::TriageOutcome;
pub use triage_state::{derive_triage_state, FindingTriageState, StableLifecycleStatus};
