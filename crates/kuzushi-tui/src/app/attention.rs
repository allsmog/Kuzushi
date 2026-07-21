use super::{GuidedScanStage, SetupEditor, ShellApp};
use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
use kuzushi_core::WorkflowPhase;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AttentionKind {
    Approval,
    OperatorQuestion,
    Credential,
    PartialResult,
    ResultDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttentionRoute {
    Confirmation,
    Activity,
    Setup,
    Workbench(WorkflowPhase),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttentionItem {
    pub(crate) id: String,
    pub(crate) kind: AttentionKind,
    pub(crate) route: AttentionRoute,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AttentionBroker {
    items: Vec<AttentionItem>,
}

impl AttentionBroker {
    pub(crate) fn from_app(app: &ShellApp) -> Self {
        let mut items = Vec::new();
        collect_approval(app, &mut items);
        collect_operator_question(app, &mut items);
        collect_guided_question(app, &mut items);
        collect_credential_gate(app, &mut items);
        collect_phase_results(app, &mut items);
        items.sort_by_key(|item| (item.kind, route_order(item.route)));
        Self { items }
    }

    pub(crate) fn primary(&self) -> Option<&AttentionItem> {
        self.items.first()
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn footer_segment(&self) -> Option<String> {
        let primary = self.primary()?;
        let subject = if self.len() == 1 {
            primary.kind.footer_subject().to_string()
        } else {
            format!("{} items need attention", self.len())
        };
        Some(format!("{subject} · {}", primary.route.hint()))
    }
}

impl AttentionKind {
    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Approval => "APPROVAL REQUIRED",
            Self::OperatorQuestion => "WAITING INPUT",
            Self::Credential => "CREDENTIALS REQUIRED",
            Self::PartialResult => "PARTIAL RESULT",
            Self::ResultDisposition => "RESULT READY",
        }
    }

    const fn footer_subject(self) -> &'static str {
        match self {
            Self::Approval => "1 approval needed",
            Self::OperatorQuestion => "1 question waiting",
            Self::Credential => "1 credential needed",
            Self::PartialResult => "1 partial result",
            Self::ResultDisposition => "1 result ready",
        }
    }
}

impl AttentionRoute {
    const fn hint(self) -> &'static str {
        match self {
            Self::Confirmation => "confirm",
            Self::Activity => "/a",
            Self::Setup => "/setup",
            Self::Workbench(_) => "workbench",
        }
    }
}

fn collect_approval(app: &ShellApp, items: &mut Vec<AttentionItem>) {
    if app.advisory().pending_confirm.is_some() {
        items.push(AttentionItem {
            id: "approval".to_string(),
            kind: AttentionKind::Approval,
            route: AttentionRoute::Confirmation,
        });
    }
}

fn collect_operator_question(app: &ShellApp, items: &mut Vec<AttentionItem>) {
    let Some(question) = app
        .activity()
        .and_then(|session| session.operator_question.as_ref())
    else {
        return;
    };
    items.push(AttentionItem {
        id: question.request().request_id.clone(),
        kind: AttentionKind::OperatorQuestion,
        route: AttentionRoute::Activity,
    });
}

fn collect_guided_question(app: &ShellApp, items: &mut Vec<AttentionItem>) {
    let Some(flow) = app.engagement.guided_scan() else {
        return;
    };
    let phase = match flow.stage() {
        GuidedScanStage::MapRoute
        | GuidedScanStage::ContextPrerequisite
        | GuidedScanStage::ModuleSelection(WorkflowPhase::Map)
        | GuidedScanStage::ConfigureOptions(WorkflowPhase::Map) => WorkflowPhase::Map,
        GuidedScanStage::ModuleSelection(WorkflowPhase::Scan)
        | GuidedScanStage::ConfigureOptions(WorkflowPhase::Scan) => WorkflowPhase::Scan,
        GuidedScanStage::ModuleSelection(phase) | GuidedScanStage::ConfigureOptions(phase) => phase,
        GuidedScanStage::Running(_) | GuidedScanStage::AwaitingResult { .. } => return,
    };
    items.push(AttentionItem {
        id: format!("guided-{}", phase.word()),
        kind: AttentionKind::OperatorQuestion,
        route: AttentionRoute::Workbench(phase),
    });
}

fn collect_credential_gate(app: &ShellApp, items: &mut Vec<AttentionItem>) {
    if app.router.setup().editor() == Some(SetupEditor::Credentials) {
        items.push(AttentionItem {
            id: "credentials".to_string(),
            kind: AttentionKind::Credential,
            route: AttentionRoute::Setup,
        });
    }
}

fn collect_phase_results(app: &ShellApp, items: &mut Vec<AttentionItem>) {
    for phase in WorkflowPhase::ORDER {
        let Some(record) = app.engagement.unresolved_phase_attempt(*phase) else {
            continue;
        };
        let kind = if record.completed.outcome == PhaseAttemptOutcome::Partial {
            AttentionKind::PartialResult
        } else {
            AttentionKind::ResultDisposition
        };
        items.push(AttentionItem {
            id: record.completed.attempt_id.clone(),
            kind,
            route: AttentionRoute::Workbench(*phase),
        });
    }
}

fn route_order(route: AttentionRoute) -> usize {
    match route {
        AttentionRoute::Workbench(phase) => phase.position(),
        AttentionRoute::Confirmation | AttentionRoute::Activity | AttentionRoute::Setup => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{ConfirmKind, PendingConfirm};
    use kuzushi_core::V2Config;

    #[test]
    fn approval_has_priority_over_other_attention() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::Credentials);
        app.advisory_mut().pending_confirm = Some(PendingConfirm {
            kind: ConfirmKind::NetworkEgress,
            tool: "scanner:run".to_string(),
            target: "example.test".to_string(),
            rationale: None,
            allowlist: None,
            actor: None,
            remembered: false,
        });

        let broker = AttentionBroker::from_app(&app);

        assert_eq!(broker.len(), 2);
        assert_eq!(
            broker.primary().map(|item| item.kind),
            Some(AttentionKind::Approval)
        );
        assert_eq!(
            broker.footer_segment().as_deref(),
            Some("2 items need attention · confirm")
        );
    }

    #[test]
    fn credential_attention_contains_no_provider_or_secret_text() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::Credentials);

        let broker = AttentionBroker::from_app(&app);
        let debug = format!("{broker:?}");

        assert!(debug.contains("Credential"));
        assert!(!debug.contains("api_key"));
        assert!(!debug.contains("secret"));
    }
}
