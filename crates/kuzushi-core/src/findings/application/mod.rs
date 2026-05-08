use super::domain::*;
use super::presentation::{proof_state_label, runtime_validation_label};
use serde::Serialize;

mod projections;

pub use projections::{
    finding_confidence_label, finding_cwe_label, finding_evidence_preview, finding_location,
    finding_source_label, finding_verdict_label, project_finding, severity_badge, severity_icon,
    FindingProjection,
};
