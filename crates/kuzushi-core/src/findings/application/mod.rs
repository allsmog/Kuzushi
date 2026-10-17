mod scan_assessment;
use super::domain::*;
use super::presentation::{proof_state_label, runtime_validation_label};
pub(crate) use scan_assessment::scan_rule_coverage_block;
pub use scan_assessment::{scan_reassessment_block, scan_reassessment_block_for_rule};
use serde::Serialize;

mod goal_review;
pub(crate) use goal_review::read_goals;
pub use goal_review::{FindingGoalPage, FindingGoalRow};
mod batch_occurrence;
mod context_matrix_occurrence;
mod scope_study_occurrence;
pub use context_matrix_occurrence::{
    derive_context_matrix_occurrence_report, read_context_matrix_occurrence_report,
    ContextCaseOccurrenceReport, ContextMatrixOccurrenceReport,
};
pub use scope_study_occurrence::{
    derive_scope_study_occurrence_report, read_scope_study_occurrence_report,
    ScopeStudyOccurrenceReport,
};
mod cross_tool_clusters;
mod effective_review_state;
mod finding_page;
mod review_groups;
pub use review_groups::{
    read_finding_groups, read_finding_groups_cancellable, FindingGroupDiagnostics,
    FindingGroupMember, FindingGroupsPage, FindingGroupsRequest, FindingReviewGroup,
};
mod finding_review_gate;
pub use finding_page::{
    finding_page_anchor, finding_page_anchor_index, finding_page_continuity_anchor,
    read_finding_page, read_finding_page_snapshot, FindingListPage, FindingPageAnchorMissing,
    FindingPageMetadata, FindingPageOrder, FindingPageRequest, FindingPageSnapshot,
};
mod generic_tool_findings;
mod identity_audit;
mod identity_fold_projection;
mod identity_policy_approval;
mod projections;
mod review_decision_conflict;
mod reviewed_refutation;
mod run_delta;
mod scan_comparison;
pub(crate) use run_delta::{
    commit_observed_findings, commit_observed_findings_with_counts,
    commit_observed_findings_with_status, emit_finding_delta, emit_persisted_finding_delta,
};

pub use batch_occurrence::{
    derive_batch_gate_binding, derive_batch_occurrence_report,
    derive_batch_occurrence_report_for_controller, finding_projection_key, BatchOccurrenceReport,
    BatchOccurrenceRow, BatchTrialReport, IdentityFoldPolicy,
};
pub use cross_tool_clusters::{
    derive_cross_tool_cluster_report, CrossToolCandidateCluster, CrossToolClusterBasis,
    CrossToolClusterMember, CrossToolClusterReport,
};
pub use effective_review_state::{
    decision_is_review_actionable, finding_is_review_actionable, review_decision_history_for,
    review_verdict_is_actionable, EffectiveReviewDecision, EffectiveReviewStateIndex,
};
pub(crate) use finding_review_gate::{
    load_finding_review_gate, FindingReviewGate, ReviewConfirmation, MISSING_CONFIRMATION_GUIDANCE,
};
pub(crate) use generic_tool_findings::{
    normalize_agent_json_findings, persist_tool_findings, persist_tool_findings_to,
    persist_tool_findings_to_with_status, render_generic_findings_output, GenericPersistedRun,
    ToolFindingsSink,
};
pub use identity_audit::{
    audit_finding_identities, FindingIdentityAuditGroup, FindingIdentityAuditIssueKind,
    FindingIdentityAuditReport,
};
pub(crate) use identity_fold_projection::project_finding_generations;
pub(in crate::findings) use identity_fold_projection::representative_fingerprints_for_members;
pub use identity_policy_approval::{
    approve_finding_identity_audit, build_finding_identity_audit_evidence,
    current_finding_identity_audit_evidence, identity_audit_approval_receipt_path,
    resolve_identity_policy_defaults, FindingIdentityAuditApprovalReceipt,
    FindingIdentityAuditApprovalRequest, FindingIdentityAuditDisposition,
    FindingIdentityAuditEvidence, FindingIdentityAuditGroupDisposition,
    IdentityPolicyApprovalStatus, IdentityPolicyDefaults, IDENTITY_AUDIT_APPROVAL_DIR,
    IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION, IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION,
};
pub use projections::{
    finding_confidence_label, finding_cwe_label, finding_evidence_preview, finding_location,
    finding_remediation_hint, finding_source_label, finding_verdict_label, project_finding,
    severity_badge, severity_icon, FindingProjection,
};
pub use review_decision_conflict::ReviewDecisionConflict;
pub use reviewed_refutation::{
    derive_reviewed_refutation_report, RefutationCohortFact, RefutationCohortKey,
    RefutationPopulation, RefutationPopulationStats, ReviewedRefutationCohort,
    ReviewedRefutationPrior, ReviewedRefutationReport,
};
pub use scan_comparison::{
    compare_scan_runs, ComparedFinding, ScanComparisonClass, ScanFindingSignature,
    ScanObservationPresence, ScanRunComparison, ScanUncertainMatch,
};
