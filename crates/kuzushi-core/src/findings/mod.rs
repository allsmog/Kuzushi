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
    compare_scan_runs, finding_confidence_label, finding_cwe_label, finding_evidence_preview,
    finding_location, finding_remediation_hint, finding_source_label, finding_verdict_label,
    project_finding, severity_badge, severity_icon, ComparedFinding, FindingProjection,
    ReviewDecisionConflict, ScanComparisonClass, ScanFindingSignature, ScanRunComparison,
    ScanUncertainMatch,
};
pub(crate) use application::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output,
    GenericPersistedRun,
};
#[cfg(test)]
pub(crate) use domain::test_verified_receipt;
pub use domain::{
    compute_dedup_key, compute_root_cause_key, compute_source_signature, derive_triage_state,
    extract_cwe, ground_finding_location, grounding_prompt_note, is_attack_chain_finding,
    normalize_cwe, ConfidenceBand, DismissReason, Finding, FindingEvidence, FindingSource,
    FindingTriageState, GroundingStatus, PatchAttempt, PatchAttemptSummary,
    PatchDetectorReplayOutcome, PatchEmpiricalOutcome, PatchLifecycleFile, PatchLifecycleRecord,
    PatchLifecycleState, PatchProvenance, PatchResult, PatchReverificationCaseKind,
    PatchReverificationFileHash, PatchReverificationReceipt, PatchReverificationStep,
    PatchReverificationTarget, PatchStatus, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, ProofConfidence, RefuteReason, ReviewDecision,
    ReviewDecisionProvenance, ReviewDecisionRecord, ReviewDecisionVerdict, Severity,
    StableLifecycleStatus, StaticProofState,
    StaticProofStateEvent, TriageAuthor, TriageOutcome, TriageVerdict, VerificationProvenance,
    VulnSource, PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
};
pub(crate) use domain::{
    all_components_deterministic, is_deterministic_scanner, is_runtime_proof_state, now_isoish,
    safe_target_path, tool_components,
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
