mod application;
mod domain;
pub mod import;
pub mod ingest_contract;
mod persistence;
pub mod presentation;

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
    derive_batch_occurrence_report_for_controller, derive_cross_tool_cluster_report,
    derive_reviewed_refutation_report, finding_confidence_label, finding_cwe_label,
    finding_evidence_preview, finding_is_review_actionable, finding_location,
    finding_projection_key, finding_remediation_hint, finding_source_label, finding_verdict_label,
    project_finding, review_decision_history_for, review_verdict_is_actionable, severity_badge,
    severity_icon, BatchOccurrenceReport, BatchOccurrenceRow, BatchTrialReport, ComparedFinding,
    CrossToolCandidateCluster, CrossToolClusterBasis, CrossToolClusterMember,
    CrossToolClusterReport, EffectiveReviewDecision, EffectiveReviewStateIndex,
    FindingIdentityAuditApprovalReceipt, FindingIdentityAuditApprovalRequest,
    FindingIdentityAuditDisposition, FindingIdentityAuditEvidence, FindingIdentityAuditGroup,
    FindingIdentityAuditGroupDisposition, FindingIdentityAuditIssueKind,
    FindingIdentityAuditReport, FindingProjection, IdentityFoldPolicy,
    IdentityPolicyApprovalStatus, IdentityPolicyDefaults, RefutationCohortFact,
    RefutationCohortKey, RefutationPopulation, RefutationPopulationStats, ReviewDecisionConflict,
    ReviewedRefutationCohort, ReviewedRefutationPrior, ReviewedRefutationReport,
    ScanComparisonClass, ScanFindingSignature, ScanRunComparison, ScanUncertainMatch,
    IDENTITY_AUDIT_APPROVAL_DIR, IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
    IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION,
};
pub(crate) use application::{
    commit_observed_findings, emit_finding_delta, emit_persisted_finding_delta,
    load_finding_review_gate, normalize_agent_json_findings, persist_tool_findings,
    persist_tool_findings_to, render_generic_findings_output, FindingReviewGate,
    GenericPersistedRun, ReviewConfirmation, ToolFindingsSink, MISSING_CONFIRMATION_GUIDANCE,
};
#[cfg(test)]
pub(crate) use domain::test_verified_receipt;
pub(crate) use domain::{
    all_components_deterministic, is_deterministic_scanner, is_runtime_proof_state, now_isoish,
    safe_target_path, tool_components,
};
pub use domain::{
    auto_triage_propagation_basis, compute_dedup_key, compute_root_cause_key,
    compute_source_signature, derive_triage_state, extract_cwe, ground_finding_location,
    grounding_prompt_note, is_attack_chain_finding, normalize_cwe, ConfidenceBand, DismissReason,
    Finding, FindingEvidence, FindingIdentityBasis, FindingSource, FindingTriageState,
    GroundingStatus, PatchAttempt, PatchAttemptSummary, PatchDetectorReplayOutcome,
    PatchEmpiricalOutcome, PatchLifecycleFile, PatchLifecycleRecord, PatchLifecycleState,
    PatchProvenance, PatchResult, PatchReverificationCaseKind, PatchReverificationFileHash,
    PatchReverificationReceipt, PatchReverificationStep, PatchReverificationTarget, PatchStatus,
    PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, ProofConfidence,
    RefuteReason, ReviewDecision, ReviewDecisionPropagation, ReviewDecisionProvenance,
    ReviewDecisionRecord, ReviewDecisionSubject, ReviewDecisionVerdict, Severity,
    StableLifecycleStatus, StaticProofState, StaticProofStateEvent, TriageAuthor, TriageOutcome,
    TriageVerdict, VerificationProvenance, VulnSource, PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
};
pub use persistence::{
    threat_model_document_sha256, FindingAuditEvent, FindingStore, ModelRekeyRequest,
    ObservationSourceRef, SuppressionLifecycleEvent, ThreatModelVersionRecord,
};
pub use presentation::{
    compare_findings_by_confidence, dataflow_evidence_rows, finding_lifecycle_status,
    finding_next_action, format_finding_alias, format_stage_note, parse_finding_alias,
    parse_stage_note, proof_ladder_state, proof_state_label, resolve_finding_alias,
    runtime_validation_label, runtime_validation_summary, security_case_projection,
    sorted_finding_alias_indices, sorted_finding_aliases, stable_finding_alias,
    static_proof_summary, DataflowEvidenceRow, FindingDetailReport, FindingLifecycleStatusFilter,
    FindingListFilter, FindingListReport, FindingNextAction, FindingReviewCompletenessFilter,
    FindingVerdictFilter, ProofLadderState, RuntimeValidationSummary, SecurityCaseClaim,
    SecurityCaseProjection, SecurityCaseProof, SecurityCaseSource, StaticProofSummary,
    VerificationStageDisclosure, DATAFLOW_EVIDENCE_SUBJECT, SECURITY_CASE_SCHEMA_VERSION,
    STAGE_NOTE_SENTINEL,
};
