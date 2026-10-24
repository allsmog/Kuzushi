use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod goal_relevance;
pub(crate) use goal_relevance::GOAL_RELEVANCE_SUBJECT;
pub use goal_relevance::{FindingGoalAssessment, FindingGoalBasis, GoalRelevance};
mod confidence_band;
mod deterministic_scanners;
mod evidence_kind;
mod extract_cwe;
mod finding_identity;
mod finding_record;
mod source_history;
pub use source_history::distinct_recorded_source_count;
pub(crate) use source_history::merge_ordered_source_histories;
mod from_semgrep;
mod grounding;
mod identity_propagation;
mod now_isoish;
mod patch_lifecycle;
mod patch_reverification;
mod patch_status;
mod persisted_results;
mod proof_confidence;
mod relationship;
mod reported_source_path;
pub(crate) use reported_source_path::normalize_reported_source_path;
mod review_decision;
mod review_decision_counts;
pub use review_decision_counts::ReviewDecisionCounts;
mod review_source_capture;
pub use review_source_capture::{ReviewCapturedFile, ReviewCapturedFileState, ReviewSourceCapture};
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
pub use finding_identity::{
    compute_finding_identity_id, finding_identity_alias, finding_observation_identity,
    FindingIdentityBasis, FindingIdentityMatchTier,
};
pub(crate) use finding_identity::{
    finding_identity_key_for_captured_source, finding_identity_key_for_finding_at_target,
};
pub use finding_record::{
    compute_class_dedup_key, compute_dedup_key, compute_root_cause_key, compute_source_signature,
    is_attack_chain_finding, normalize_cwe, Finding, FindingEvidence, FindingObservationGap,
    FindingSource,
};
pub use from_semgrep::{Severity, VulnSource};
pub(crate) use grounding::safe_target_path;
pub(crate) use grounding::{ground_against_source, grounding_read_error};
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
pub use relationship::{
    FindingRelationship, FindingRelationshipEndpoint, FindingRelationshipKind,
    FindingRelationshipState, FINDING_RELATIONSHIP_SUBJECT,
};
mod lesson;
mod relationship_batch;
pub(crate) use lesson::FINDING_LESSON_SUBJECT;
pub use lesson::{
    FindingLesson, LessonContent, LessonGeneration, LessonOrigin, LessonRef, LessonState,
};
pub(crate) use relationship_batch::{
    validate_relationship_selection, FINDING_RELATIONSHIP_BATCH_SUBJECT,
};
pub use review_decision::{
    DismissReason, ReviewDecision, ReviewDecisionPropagation, ReviewDecisionProvenance,
    ReviewDecisionRecord, ReviewDecisionSubject, ReviewDecisionVerdict,
};
pub(crate) use static_proof_state::is_runtime_proof_state;
pub use static_proof_state::{StaticProofState, StaticProofStateEvent};
pub use triage_outcome::{RefuteReason, TriageOutcome};
pub use triage_state::{derive_triage_state, FindingTriageState, StableLifecycleStatus};
