use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod confidence_band;
mod deterministic_scanners;
mod extract_cwe;
mod finding_identity;
mod finding_record;
mod from_semgrep;
mod grounding;
mod identity_propagation;
mod now_isoish;
mod patch_lifecycle;
mod patch_reverification;
mod patch_status;
mod persisted_results;
mod proof_confidence;
mod review_decision;
mod static_proof_state;
mod triage_outcome;
mod triage_state;

pub use confidence_band::ConfidenceBand;
pub(crate) use deterministic_scanners::{
    all_components_deterministic, is_deterministic_scanner, tool_components,
};
pub use extract_cwe::extract_cwe;
#[cfg(test)]
pub(crate) use finding_identity::finding_identity_key_for_finding;
pub(crate) use finding_identity::finding_identity_key_for_finding_at_target;
pub use finding_identity::{
    compute_finding_identity_id, finding_identity_alias, FindingIdentityBasis,
    FindingIdentityMatchTier,
};
pub use finding_record::{
    compute_class_dedup_key, compute_dedup_key, compute_root_cause_key, compute_source_signature,
    is_attack_chain_finding, normalize_cwe, Finding, FindingEvidence, FindingSource,
};
pub use from_semgrep::{Severity, VulnSource};
pub(crate) use grounding::safe_target_path;
pub use grounding::{ground_finding_location, grounding_prompt_note, GroundingStatus};
pub use identity_propagation::auto_triage_propagation_basis;
pub(crate) use now_isoish::now_isoish;
pub use patch_lifecycle::{PatchLifecycleFile, PatchLifecycleRecord, PatchLifecycleState};
#[cfg(test)]
pub(crate) use patch_reverification::test_verified_receipt;
pub use patch_reverification::{
    PatchDetectorReplayOutcome, PatchEmpiricalOutcome, PatchReverificationCaseKind,
    PatchReverificationFileHash, PatchReverificationReceipt, PatchReverificationStep,
    PatchReverificationTarget, PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
};
pub use patch_status::PatchStatus;
pub use persisted_results::{
    PatchAttempt, PatchAttemptSummary, PatchProvenance, PatchResult, PersistedProofVerdict,
    PersistedSandboxBackend, PersistedVerification, TriageAuthor, TriageVerdict,
    VerificationProvenance,
};
pub use proof_confidence::ProofConfidence;
pub use review_decision::{
    DismissReason, ReviewDecision, ReviewDecisionPropagation, ReviewDecisionProvenance,
    ReviewDecisionRecord, ReviewDecisionVerdict,
};
pub(crate) use static_proof_state::is_runtime_proof_state;
pub use static_proof_state::{StaticProofState, StaticProofStateEvent};
pub use triage_outcome::{RefuteReason, TriageOutcome};
pub use triage_state::{derive_triage_state, FindingTriageState, StableLifecycleStatus};
