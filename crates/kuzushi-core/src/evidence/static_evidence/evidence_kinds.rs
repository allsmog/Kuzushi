use super::*;

pub(crate) const STATIC_EVIDENCE_DB_NAME: &str = "static-evidence.sqlite3";

pub const STATIC_EVIDENCE_NODE_KINDS: &[StaticEvidenceNodeKind] = &[
    StaticEvidenceNodeKind::CodeSpan,
    StaticEvidenceNodeKind::ScannerSignal,
    StaticEvidenceNodeKind::Source,
    StaticEvidenceNodeKind::Sink,
    StaticEvidenceNodeKind::DataflowStep,
    StaticEvidenceNodeKind::Sanitizer,
    StaticEvidenceNodeKind::Guard,
    StaticEvidenceNodeKind::AttackSurface,
    StaticEvidenceNodeKind::TriageClaim,
    StaticEvidenceNodeKind::ReportClaim,
];

pub const STATIC_EVIDENCE_EDGE_KINDS: &[StaticEvidenceEdgeKind] = &[
    StaticEvidenceEdgeKind::Supports,
    StaticEvidenceEdgeKind::DerivedFrom,
    StaticEvidenceEdgeKind::FlowsTo,
    StaticEvidenceEdgeKind::GuardedBy,
    StaticEvidenceEdgeKind::SanitizedBy,
    StaticEvidenceEdgeKind::Contradicts,
    StaticEvidenceEdgeKind::ReportedAs,
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticEvidenceNodeKind {
    CodeSpan,
    ScannerSignal,
    Source,
    Sink,
    DataflowStep,
    Sanitizer,
    Guard,
    AttackSurface,
    TriageClaim,
    ReportClaim,
}

impl StaticEvidenceNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CodeSpan => "code_span",
            Self::ScannerSignal => "scanner_signal",
            Self::Source => "source",
            Self::Sink => "sink",
            Self::DataflowStep => "dataflow_step",
            Self::Sanitizer => "sanitizer",
            Self::Guard => "guard",
            Self::AttackSurface => "attack_surface",
            Self::TriageClaim => "triage_claim",
            Self::ReportClaim => "report_claim",
        }
    }
}

impl TryFrom<&str> for StaticEvidenceNodeKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim() {
            "code_span" | "code-span" => Ok(Self::CodeSpan),
            "scanner_signal" | "scanner-signal" => Ok(Self::ScannerSignal),
            "source" => Ok(Self::Source),
            "sink" => Ok(Self::Sink),
            "dataflow_step" | "dataflow-step" => Ok(Self::DataflowStep),
            "sanitizer" => Ok(Self::Sanitizer),
            "guard" => Ok(Self::Guard),
            "attack_surface" | "attack-surface" => Ok(Self::AttackSurface),
            "triage_claim" | "triage-claim" => Ok(Self::TriageClaim),
            "report_claim" | "report-claim" => Ok(Self::ReportClaim),
            other => anyhow::bail!("unknown static evidence node kind {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticEvidenceEdgeKind {
    Supports,
    DerivedFrom,
    FlowsTo,
    GuardedBy,
    SanitizedBy,
    Contradicts,
    ReportedAs,
}
