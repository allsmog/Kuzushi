use super::domain::*;
use serde::Serialize;

mod detail;
mod evidence_origin;
pub use evidence_origin::evidence_origin_label;
mod finding_lines;
mod observation_gap;
pub mod pr_comment;
mod reporting;
mod study_severity;

pub(crate) use finding_lines::top_finding_lines;
pub use observation_gap::observation_gap_note;
pub use study_severity::batch_severity_summary;

pub use detail::{
    dataflow_evidence_rows, finding_lifecycle_status, finding_next_action, format_stage_note,
    parse_stage_note, proof_ladder_state, proof_state_label, runtime_validation_label,
    runtime_validation_summary, security_case_projection, static_proof_summary,
    DataflowEvidenceRow, FindingDetailReport, FindingNextAction, ProofLadderState,
    RuntimeValidationSummary, SecurityCaseClaim, SecurityCaseProjection, SecurityCaseProof,
    SecurityCaseSource, StaticProofSummary, VerificationStageDisclosure, DATAFLOW_EVIDENCE_SUBJECT,
    SECURITY_CASE_SCHEMA_VERSION, STAGE_NOTE_SENTINEL,
};
pub use reporting::{
    compare_findings_by_confidence, format_finding_alias, parse_finding_alias,
    resolve_finding_alias, sorted_finding_alias_indices, sorted_finding_aliases,
    stable_finding_alias, FindingLifecycleStatusFilter, FindingListFilter, FindingListReport,
    FindingReviewCompletenessFilter, FindingVerdictFilter,
};
