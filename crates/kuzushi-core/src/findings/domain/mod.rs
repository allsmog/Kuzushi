use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod confidence_band;
mod extract_cwe;
mod finding_identity;
mod finding_record;
mod from_semgrep;
mod grounding;
mod now_isoish;
mod patch_lifecycle;
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
    compute_class_dedup_key, compute_dedup_key, compute_root_cause_key, compute_source_signature,
    is_attack_chain_finding,
    normalize_cwe, Finding, FindingEvidence, FindingSource,
};
pub use from_semgrep::{Severity, VulnSource};
pub(crate) use grounding::safe_target_path;
pub use grounding::{ground_finding_location, grounding_prompt_note, GroundingStatus};
pub(crate) use now_isoish::now_isoish;
pub use patch_lifecycle::{PatchLifecycleFile, PatchLifecycleRecord, PatchLifecycleState};
pub use patch_status::PatchStatus;
pub use persisted_results::{
    PatchAttempt, PatchAttemptSummary, PatchProvenance, PatchResult, PersistedProofVerdict,
    PersistedSandboxBackend, PersistedVerification, TriageAuthor, TriageVerdict,
};
pub use proof_confidence::ProofConfidence;
pub use review_decision::{
    DismissReason, ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict,
};
pub(crate) use static_proof_state::is_runtime_proof_state;
pub use static_proof_state::{StaticProofState, StaticProofStateEvent};
pub use triage_outcome::{RefuteReason, TriageOutcome};
pub use triage_state::{derive_triage_state, FindingTriageState, StableLifecycleStatus};
