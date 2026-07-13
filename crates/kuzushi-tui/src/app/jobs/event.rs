use super::*;

#[derive(Debug)]
pub(crate) enum ShellEvent {
    Trace(RunTraceStep),
    Scan(ScanEvent),
    Tool(ToolEvent),
    Agent(AgentEvent),
    Plan(PlanEvent),
    Threat(ThreatPatchEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum JobKind {
    Run,
    Agent,
    Plan,
    Threat,
}

impl ShellEvent {
    pub(crate) fn kind(&self) -> JobKind {
        match self {
            Self::Trace(_) | Self::Scan(_) | Self::Tool(_) => JobKind::Run,
            Self::Agent(_) => JobKind::Agent,
            Self::Plan(_) => JobKind::Plan,
            Self::Threat(_) => JobKind::Threat,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        match self {
            Self::Trace(_) | Self::Scan(ScanEvent::Stage(_)) => false,
            Self::Scan(ScanEvent::Finished { .. } | ScanEvent::Failed { .. }) => true,
            Self::Tool(
                ToolEvent::Finished { .. } | ToolEvent::Failed { .. } | ToolEvent::Refused { .. },
            ) => true,
            Self::Agent(AgentEvent::Answered { .. } | AgentEvent::Failed { .. }) => true,
            Self::Plan(PlanEvent::Proposed { .. } | PlanEvent::Failed { .. }) => true,
            Self::Threat(
                ThreatPatchEvent::Proposed { .. }
                | ThreatPatchEvent::Answer { .. }
                | ThreatPatchEvent::Failed { .. },
            ) => true,
        }
    }

    pub(super) fn failure(kind: JobKind, label: &str, error: String) -> Self {
        match kind {
            JobKind::Run if label == "scan" => Self::Scan(ScanEvent::Failed { error }),
            JobKind::Run => Self::Tool(ToolEvent::Failed {
                tool_name: label.to_string(),
                error,
            }),
            JobKind::Agent => Self::Agent(AgentEvent::Failed {
                error,
                audit: disconnected_job_audit(),
            }),
            JobKind::Plan => Self::Plan(PlanEvent::Failed {
                error,
                audit: disconnected_job_audit(),
            }),
            JobKind::Threat => Self::Threat(ThreatPatchEvent::Failed {
                error,
                audit: disconnected_job_audit(),
            }),
        }
    }
}

fn disconnected_job_audit() -> AgentCallAudit {
    AgentCallAudit {
        model: "unknown".to_string(),
        provider: "unknown".to_string(),
        prompt_hash: "jobhub-panic-guard".to_string(),
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        call_attempted: true,
    }
}
