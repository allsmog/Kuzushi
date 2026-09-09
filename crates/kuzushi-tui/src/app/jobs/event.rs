use super::*;

#[derive(Debug)]
pub(crate) enum ShellEvent {
    RunItem(kuzushi_core::run_lifecycle::RunItemEnvelopeV1),
    RunItemsDurable {
        run_id: String,
        range: kuzushi_core::run_lifecycle::CommittedRange,
    },
    RunItemsDerivativesApplied {
        run_id: String,
        range: kuzushi_core::run_lifecycle::CommittedRange,
    },
    RunItemsFault {
        run_id: String,
        fault: kuzushi_core::run_lifecycle::RunItemWriterFault,
    },
    RunItemsDeliveryFault {
        run_id: String,
        fault: kuzushi_core::run_lifecycle::RunItemDeliveryFault,
    },
    Scan(ScanEvent),
    Tool(ToolEvent),
    Agent(AgentEvent),
    OperatorQuestion(OperatorQuestionEnvelope),
    OperatorQuestionCompleted(OperatorQuestionCompleted),
    CredentialQuestionRouted {
        request_id: String,
        run_id: String,
    },
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
    pub(crate) fn is_run_lifecycle(&self) -> bool {
        matches!(
            self,
            Self::Agent(AgentEvent::ResponseText(_))
                | Self::RunItem(_)
                | Self::RunItemsDurable { .. }
                | Self::RunItemsDerivativesApplied { .. }
                | Self::RunItemsFault { .. }
                | Self::RunItemsDeliveryFault { .. }
        )
    }

    pub(crate) fn is_operator_interaction(&self) -> bool {
        matches!(
            self,
            Self::OperatorQuestion(_)
                | Self::OperatorQuestionCompleted(_)
                | Self::CredentialQuestionRouted { .. }
        )
    }

    pub(crate) fn kind(&self) -> JobKind {
        match self {
            Self::Agent(AgentEvent::ResponseText(_))
            | Self::RunItem(_)
            | Self::RunItemsDurable { .. }
            | Self::RunItemsDerivativesApplied { .. }
            | Self::RunItemsFault { .. }
            | Self::RunItemsDeliveryFault { .. }
            | Self::Scan(_)
            | Self::Tool(_) => JobKind::Run,
            Self::Agent(_)
            | Self::OperatorQuestion(_)
            | Self::OperatorQuestionCompleted(_)
            | Self::CredentialQuestionRouted { .. } => JobKind::Agent,
            Self::Plan(_) => JobKind::Plan,
            Self::Threat(_) => JobKind::Threat,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        match self {
            Self::Agent(AgentEvent::ResponseText(_))
            | Self::RunItem(_)
            | Self::RunItemsDurable { .. }
            | Self::RunItemsDerivativesApplied { .. }
            | Self::RunItemsFault { .. }
            | Self::RunItemsDeliveryFault { .. }
            | Self::Scan(ScanEvent::Stage(_))
            | Self::OperatorQuestion(_)
            | Self::OperatorQuestionCompleted(_)
            | Self::CredentialQuestionRouted { .. } => false,
            Self::Scan(ScanEvent::Finished { .. } | ScanEvent::Failed { .. }) => true,
            Self::Tool(
                ToolEvent::Finished { .. }
                | ToolEvent::Failed { .. }
                | ToolEvent::Refused { .. }
                | ToolEvent::ObservedFinished { .. }
                | ToolEvent::ObservedFailed { .. }
                | ToolEvent::AuthenticationFailed { .. },
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
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        call_attempted: true,
        tool_policy_receipt: None,
        failure: None,
    }
}
