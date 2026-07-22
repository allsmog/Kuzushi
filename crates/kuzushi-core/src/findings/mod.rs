mod application;
mod domain;
pub mod import;
pub mod ingest_contract;
mod persistence;
pub mod presentation;

#[cfg(test)]
mod tests;

pub use application::{
    finding_confidence_label, finding_cwe_label, finding_evidence_preview, finding_location,
    finding_remediation_hint, finding_source_label, finding_verdict_label, project_finding,
    severity_badge, severity_icon, FindingProjection,
};
pub(crate) use application::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output,
    GenericPersistedRun,
};
pub(crate) use domain::{is_runtime_proof_state, now_isoish};
pub use domain::{
    compute_dedup_key, compute_root_cause_key, compute_source_signature, derive_triage_state,
    extract_cwe, normalize_cwe, ConfidenceBand, DismissReason, Finding, FindingEvidence,
    FindingSource, FindingTriageState, PatchAttempt, PatchAttemptSummary, PatchLifecycleFile,
    PatchLifecycleRecord, PatchLifecycleState, PatchProvenance, PatchResult, PatchStatus,
    PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, ProofConfidence,
    ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, Severity, StableLifecycleStatus,
    StaticProofState, StaticProofStateEvent, TriageAuthor, TriageOutcome, TriageVerdict,
    VulnSource,
};
pub use persistence::{
    threat_model_document_sha256, FindingStore, ObservationSourceRef,
    SuppressionLifecycleEvent, ThreatModelVersionRecord,
};
pub use presentation::{
    compare_findings_by_confidence, finding_lifecycle_status, finding_next_action,
    format_finding_alias, parse_finding_alias, proof_ladder_state, proof_state_label,
    resolve_finding_alias, runtime_validation_label, runtime_validation_summary,
    sorted_finding_alias_indices, sorted_finding_aliases, stable_finding_alias,
    static_proof_summary, FindingDetailReport, FindingLifecycleStatusFilter, FindingListFilter,
    FindingListReport, FindingNextAction, FindingReviewCompletenessFilter, FindingVerdictFilter,
    ProofLadderState, RuntimeValidationSummary, StaticProofSummary,
};
