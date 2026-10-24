pub(crate) use application::scan_rule_coverage_block;
pub use application::{scan_reassessment_block, scan_reassessment_block_for_rule};
mod application;
pub(crate) use application::read_goals;
pub use application::{FindingGoalPage, FindingGoalRow};
mod domain;
pub use domain::distinct_recorded_source_count;
pub(crate) use domain::merge_ordered_source_histories;
pub(crate) use domain::normalize_reported_source_path;
pub(crate) use domain::FINDING_LESSON_SUBJECT;
pub(crate) use domain::GOAL_RELEVANCE_SUBJECT;
pub(crate) use domain::{validate_relationship_selection, FINDING_RELATIONSHIP_BATCH_SUBJECT};
pub use domain::{FindingGoalAssessment, FindingGoalBasis, GoalRelevance};
pub use domain::{
    FindingLesson, LessonContent, LessonGeneration, LessonOrigin, LessonRef, LessonState,
};
pub use domain::{ReviewCapturedFile, ReviewCapturedFileState, ReviewSourceCapture};
pub use persistence::FindingLessonPage;
pub(crate) use persistence::{CapturedFindingSources, FindingSourceSnapshot};
pub mod import;
pub mod ingest_contract;
pub(crate) mod persistence;
pub use domain::{
    FindingRelationship, FindingRelationshipEndpoint, FindingRelationshipKind,
    FindingRelationshipState, FINDING_RELATIONSHIP_SUBJECT,
};
pub mod presentation;
pub use application::{
    read_finding_groups, read_finding_groups_cancellable, FindingGroupDiagnostics,
    FindingGroupMember, FindingGroupsPage, FindingGroupsRequest, FindingReviewGroup,
};
pub use persistence::FindingRelationshipPage;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

pub use application::{
    approve_finding_identity_audit, build_finding_identity_audit_evidence,
    current_finding_identity_audit_evidence, identity_audit_approval_receipt_path,
    resolve_identity_policy_defaults,
};
pub use application::{
    audit_finding_identities, compare_scan_runs, decision_is_review_actionable,
    derive_batch_gate_binding, derive_batch_occurrence_report,
    derive_batch_occurrence_report_for_controller, derive_context_matrix_occurrence_report,
    derive_cross_tool_cluster_report, derive_reviewed_refutation_report, finding_confidence_label,
    finding_cwe_label, finding_evidence_preview, finding_is_review_actionable, finding_location,
    finding_projection_key, finding_remediation_hint, finding_source_label, finding_verdict_label,
    project_finding, read_context_matrix_occurrence_report, review_decision_history_for,
    review_verdict_is_actionable, severity_badge, severity_icon, BatchOccurrenceReport,
    BatchOccurrenceRow, BatchReceiptPending, BatchTrialReport, ComparedFinding,
    ContextCaseOccurrenceReport, ContextMatrixOccurrenceReport, CrossToolCandidateCluster,
    CrossToolClusterBasis, CrossToolClusterMember, CrossToolClusterReport, EffectiveReviewDecision,
    EffectiveReviewStateIndex, FindingIdentityAuditApprovalReceipt,
    FindingIdentityAuditApprovalRequest, FindingIdentityAuditDisposition,
    FindingIdentityAuditEvidence, FindingIdentityAuditGroup, FindingIdentityAuditGroupDisposition,
    FindingIdentityAuditIssueKind, FindingIdentityAuditReport, FindingProjection,
    IdentityFoldPolicy, IdentityPolicyApprovalStatus, IdentityPolicyDefaults, RefutationCohortFact,
    RefutationCohortKey, RefutationPopulation, RefutationPopulationStats, ReviewDecisionConflict,
    ReviewedRefutationCohort, ReviewedRefutationPrior, ReviewedRefutationReport,
    ScanComparisonClass, ScanFindingSignature, ScanObservationPresence, ScanRunComparison,
    ScanUncertainMatch, IDENTITY_AUDIT_APPROVAL_DIR, IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
    IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION,
};
pub(crate) use application::{
    commit_observed_findings, commit_observed_findings_with_counts,
    commit_observed_findings_with_status, emit_finding_delta, emit_persisted_finding_delta,
    load_finding_review_gate, normalize_agent_json_findings, persist_tool_findings,
    persist_tool_findings_to, persist_tool_findings_to_with_status, render_generic_findings_output,
    FindingReviewGate, GenericPersistedRun, ReviewConfirmation, ToolFindingsSink,
    MISSING_CONFIRMATION_GUIDANCE,
};
pub use application::{
    derive_scope_study_occurrence_report, read_scope_study_occurrence_report,
    ScopeStudyOccurrenceReport,
};
pub use application::{
    finding_page_anchor, finding_page_anchor_index, finding_page_continuity_anchor,
    read_finding_page, read_finding_page_snapshot, FindingListPage, FindingPageAnchorMissing,
    FindingPageMetadata, FindingPageOrder, FindingPageRequest, FindingPageSnapshot,
    FindingScopeFilterReceipt,
};
#[cfg(test)]
pub(crate) use domain::test_verified_receipt;
pub(crate) use domain::{
    all_components_deterministic, ground_against_source, grounding_read_error,
    is_deterministic_scanner, is_runtime_proof_state, now_isoish, safe_target_path,
    tool_components,
};
pub use domain::{
    auto_triage_propagation_basis, compute_dedup_key, compute_root_cause_key,
    compute_source_signature, derive_triage_state, extract_cwe, finding_observation_identity,
    ground_finding_location, grounding_prompt_note, is_attack_chain_finding, normalize_cwe,
    ConfidenceBand, DismissReason, Finding, FindingEvidence, FindingIdentityBasis,
    FindingObservationGap, FindingSource, FindingTriageState, GroundingStatus, PatchAttempt,
    PatchAttemptSummary, PatchDetectorReplayOutcome, PatchEmpiricalOutcome, PatchLifecycleFile,
    PatchLifecycleRecord, PatchLifecycleState, PatchProvenance, PatchResult,
    PatchReverificationCaseKind, PatchReverificationFileHash, PatchReverificationReceipt,
    PatchReverificationStep, PatchReverificationTarget, PatchStatus, PersistedProofVerdict,
    PersistedSandboxBackend, PersistedVerification, ProofConfidence, RefuteReason, ReviewDecision,
    ReviewDecisionCounts, ReviewDecisionPropagation, ReviewDecisionProvenance,
    ReviewDecisionRecord, ReviewDecisionSubject, ReviewDecisionVerdict, Severity,
    StableLifecycleStatus, StaticProofState, StaticProofStateEvent, TriageAuthor, TriageOutcome,
    TriageVerdict, VerificationProvenance, VulnSource, PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
};
pub(crate) use persistence::finding_stable_fp;
pub use persistence::{
    threat_model_document_sha256, FindingAuditEvent, FindingStore, ModelRekeyRequest,
    ObservationSourceRef, ObservedSnapshot, SuppressionLifecycleEvent, ThreatModelVersionRecord,
};
pub use presentation::{
    compare_findings_by_confidence, dataflow_evidence_rows, finding_lifecycle_status,
    finding_next_action, format_finding_alias, format_stage_note, observation_gap_note,
    parse_finding_alias, parse_stage_note, proof_ladder_state, proof_state_label,
    resolve_finding_alias, runtime_validation_label, runtime_validation_summary,
    security_case_projection, sorted_finding_alias_indices, sorted_finding_aliases,
    stable_finding_alias, static_proof_summary, DataflowEvidenceRow, FindingDetailReport,
    FindingLifecycleStatusFilter, FindingListFilter, FindingListReport, FindingNextAction,
    FindingReviewCompletenessFilter, FindingVerdictFilter, ProofLadderState,
    RuntimeValidationSummary, SecurityCaseClaim, SecurityCaseProjection, SecurityCaseProof,
    SecurityCaseSource, StaticProofSummary, VerificationStageDisclosure, DATAFLOW_EVIDENCE_SUBJECT,
    SECURITY_CASE_SCHEMA_VERSION, STAGE_NOTE_SENTINEL,
};
