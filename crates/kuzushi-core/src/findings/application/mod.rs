use super::domain::*;
use super::presentation::{proof_state_label, runtime_validation_label};
use serde::Serialize;

mod generic_tool_findings;
mod projections;

pub(crate) use generic_tool_findings::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output,
    GenericPersistedRun,
};
pub use projections::{
    finding_confidence_label, finding_cwe_label, finding_evidence_preview, finding_location,
    finding_remediation_hint, finding_source_label, finding_verdict_label, project_finding,
    severity_badge, severity_icon, FindingProjection,
};
