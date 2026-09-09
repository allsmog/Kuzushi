use super::{PhaseResultAction, PhaseResultPolicy, ShellApp, WorkflowPhase};
use crate::ui_view_models::{journey_destination_after_selection, JourneyDestination};

impl ShellApp {
    /// A receipt controls whether selection is allowed. Its generic next phase
    /// can be refined by current review/proof truth, just as selection routing
    /// re-derives that destination. Never add a withheld continuation action.
    pub(super) fn refine_phase_result_continuation(
        &self,
        phase: WorkflowPhase,
        policy: &mut PhaseResultPolicy,
    ) {
        let Some(destination) = journey_destination_after_selection(self, phase) else {
            return;
        };
        let Some(action) = policy
            .actions
            .iter_mut()
            .find(|action| is_continuation(**action))
        else {
            return;
        };
        *action = continuation_action(destination);
        policy.recommended_next = Some(continuation_recommendation(destination));
    }
}

fn is_continuation(action: PhaseResultAction) -> bool {
    matches!(
        action,
        PhaseResultAction::SelectAndContinue | PhaseResultAction::SelectAndReport
    )
}

fn continuation_action(destination: JourneyDestination) -> PhaseResultAction {
    match destination {
        JourneyDestination::Report(_) => PhaseResultAction::SelectAndReport,
        JourneyDestination::Phase(_) => PhaseResultAction::SelectAndContinue,
    }
}

fn continuation_recommendation(destination: JourneyDestination) -> String {
    match destination {
        JourneyDestination::Report(_) => "select this result and open Report".to_string(),
        JourneyDestination::Phase(phase) => {
            format!("select this result and open {}", phase.title())
        }
    }
}
