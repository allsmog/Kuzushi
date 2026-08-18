use super::{GuidedScanStage, LiveActivityPhase, SetupEditor, ShellApp};
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

    /// Full priority-ordered item list — the context rail renders every item
    /// where the footer collapses them into one segment.
    pub(crate) fn items(&self) -> &[AttentionItem] {
        &self.items
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

/// Notification candidates include terminal ad-hoc runs. They stay out of
/// the persistent attention rail because opening Activity is sufficient
/// acknowledgement; the active-id snapshot prevents repeated pings.
pub(crate) fn notification_attention_items(app: &ShellApp) -> Vec<AttentionItem> {
    let mut items = AttentionBroker::from_app(app).items;
    collect_ad_hoc_run_result(app, &mut items);
    items.sort_by_key(|item| (item.kind, route_order(item.route)));
    items
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
    pub(crate) const fn hint(self) -> &'static str {
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

fn collect_ad_hoc_run_result(app: &ShellApp, items: &mut Vec<AttentionItem>) {
    let Some(session) = app.activity() else {
        return;
    };
    if session.phase_attempt_id.is_some() {
        return;
    }
    let Some(activity) = app.live_activity() else {
        return;
    };
    let kind = match activity.phase {
        LiveActivityPhase::Partial => AttentionKind::PartialResult,
        LiveActivityPhase::Completed
        | LiveActivityPhase::Skipped
        | LiveActivityPhase::Failed
        | LiveActivityPhase::Refused => AttentionKind::ResultDisposition,
        _ => return,
    };
    items.push(AttentionItem {
        id: format!("ad-hoc-run:{}", session.run_id),
        kind,
        route: AttentionRoute::Activity,
    });
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

    #[test]
    fn terminal_ad_hoc_run_is_notification_only() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(crate::ActivitySession::new("direct-run")));
        app.set_live_activity_state(Some(crate::LiveActivity::new(
            LiveActivityPhase::Completed,
            "taint-iris:hunt",
            "complete",
        )));

        assert!(AttentionBroker::from_app(&app).items().is_empty());
        let items = notification_attention_items(&app);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "ad-hoc-run:direct-run");
        assert_eq!(items[0].route, AttentionRoute::Activity);
    }
}
