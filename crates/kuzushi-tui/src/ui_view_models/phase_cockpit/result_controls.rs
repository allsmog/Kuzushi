use crate::ui_view_models::keybindings::FooterKeybinding;
use crate::{PhaseResultCommand, ShellApp};
use kuzushi_core::WorkflowPhase;

pub(crate) fn result_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if !app.phase_result_keys_are_available() {
        return None;
    }
    let phase = app.phase_result_target_phase()?;
    let (outcome, policy) = app.phase_result_control_state(phase)?;
    let actions = crate::app::ordered_phase_result_actions(phase, outcome, &policy.actions);
    let outcome = format!("{outcome:?}").to_ascii_lowercase();
    let verified = app.verified_remediation_result_is_open(phase);
    Some(
        actions
            .iter()
            .map(|action| result_action_binding(app, *action, phase, &outcome, verified))
            .collect(),
    )
}

pub(super) fn result_action_labels_for(
    app: &ShellApp,
    actions: &[kuzushi_core::workflow_attempts::PhaseResultAction],
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> String {
    actions
        .iter()
        .map(|action| result_action_label(app, *action, phase, outcome, verified_remediation))
        .collect::<Vec<_>>()
        .join(" · ")
}

pub(super) fn result_action_label(
    app: &ShellApp,
    action: kuzushi_core::workflow_attempts::PhaseResultAction,
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> String {
    let binding = result_action_binding(app, action, phase, outcome, verified_remediation);
    format!("{} {}", binding.key, binding.label)
}

fn result_action_binding(
    app: &ShellApp,
    action: kuzushi_core::workflow_attempts::PhaseResultAction,
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> FooterKeybinding {
    use kuzushi_core::workflow_attempts::PhaseResultAction::*;
    let verb = match action {
        Select if outcome == "partial" => partial_acceptance_label(app.viewport().columns).into(),
        Select if verified_remediation => "Acknowledge verified".to_string(),
        Select => select_action_label(phase).to_string(),
        SelectAndContinue => continuation_label(app, phase),
        SelectAndReport => "Use & Report".to_string(),
        ContinueRun => "Continue".to_string(),
        Open => "Open".to_string(),
        Refine => "Refine".to_string(),
        RunAgain => "Run again".to_string(),
        Regenerate => "Regenerate".to_string(),
        // One verb per action everywhere: the guided card, the disposition
        // event, and this strip all say Discard. "Dismiss" belongs to
        // findings decisions, not attempt dispositions.
        Discard => "Discard".to_string(),
    };
    let command = PhaseResultCommand::from_action(action);
    let labels = app.ui().keymap_binding_labels(
        "phase_result",
        command.action_id(),
        &[command.default_hint()],
    );
    let key = if labels.is_empty() {
        "unbound".to_string()
    } else {
        labels.join("/")
    };
    FooterKeybinding { key, label: verb }
}

fn partial_acceptance_label(columns: u16) -> &'static str {
    if columns <= 40 {
        return "Accept";
    }
    if columns <= 80 {
        return "Accept partial";
    }
    "Acknowledge & use partial"
}

#[cfg(test)]
mod tests {
    use super::partial_acceptance_label;

    #[test]
    fn partial_acceptance_stays_explicit_at_every_supported_width() {
        assert_eq!(partial_acceptance_label(40), "Accept");
        for columns in [60, 80] {
            assert_eq!(partial_acceptance_label(columns), "Accept partial");
        }
        for columns in [96, 120, 160] {
            assert_eq!(
                partial_acceptance_label(columns),
                "Acknowledge & use partial"
            );
        }
    }
}

fn continuation_label(app: &ShellApp, phase: WorkflowPhase) -> String {
    match crate::ui_view_models::journey_destination_after_selection(app, phase) {
        Some(crate::ui_view_models::JourneyDestination::Report(_)) => "Use & Report".to_string(),
        Some(crate::ui_view_models::JourneyDestination::Phase(destination)) => {
            format!("Use & {}", destination.title())
        }
        None => continue_action_label(phase).to_string(),
    }
}

fn select_action_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "Use map",
        WorkflowPhase::Scan => "Use scan",
        WorkflowPhase::Review => "Commit decisions",
        WorkflowPhase::Prove => "Use proof set",
        WorkflowPhase::Fix => "Select patch",
    }
}

fn continue_action_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "Use & Scan",
        WorkflowPhase::Scan => "Use & Review",
        WorkflowPhase::Review => "Commit & Prove",
        WorkflowPhase::Prove => "Use & Fix",
        WorkflowPhase::Fix => "Continue",
    }
}
