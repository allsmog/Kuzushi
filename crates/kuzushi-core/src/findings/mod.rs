mod application;
mod domain;
mod persistence;
pub mod presentation;

#[cfg(test)]
mod tests;

pub use application::{
    finding_confidence_label, finding_cwe_label, finding_evidence_preview, finding_location,
    finding_source_label, finding_verdict_label, project_finding, severity_badge, severity_icon,
    FindingProjection,
};
pub(crate) use application::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output,
    GenericPersistedRun,
};
pub use domain::{
    compute_dedup_key, extract_cwe, normalize_cwe, Finding, PatchAttempt, PatchResult, PatchStatus,
    PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, Severity,
    StaticProofState, TriageOutcome, TriageVerdict, VulnSource,
};
pub use persistence::FindingStore;
pub use presentation::{
    format_finding_alias, parse_finding_alias, proof_ladder_state, proof_state_label,
    resolve_finding_alias, runtime_validation_label, sorted_finding_aliases, stable_finding_alias,
    FindingDetailReport, FindingListFilter, FindingListReport, FindingNextAction,
    FindingVerdictFilter, ProofLadderState,
};
