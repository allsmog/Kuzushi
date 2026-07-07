use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod extract_cwe;
mod finding_identity;
mod finding_record;
mod from_semgrep;
mod now_isoish;
mod patch_status;
mod persisted_results;
mod review_decision;
mod static_proof_state;
mod triage_outcome;

pub use extract_cwe::extract_cwe;
pub use finding_identity::{
    compute_finding_identity_id, finding_identity_alias, FindingIdentityMatchTier,
};
pub(crate) use finding_identity::finding_identity_key_for_finding;
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
pub use review_decision::{ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict};
pub(crate) use static_proof_state::is_runtime_proof_state;
pub use static_proof_state::{StaticProofState, StaticProofStateEvent};
pub use triage_outcome::TriageOutcome;
