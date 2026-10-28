use super::FooterKeybinding;
use crate::app::state_transitions::ViewHotkeyAction;
use crate::{InputMode, ShellApp, ShellView};

mod aliases;

pub(crate) fn campaign_reader_action_hint(app: &ShellApp) -> String {
    if app.input_mode() == InputMode::Prompt {
        return navigate_mode_hint(app);
    }
    use ViewHotkeyAction::*;
    let execution = if active_dispatcher(app) {
        CampaignKill
    } else {
        CampaignLaunch
    };
    [
        (WorkbenchReport, "report"),
        (CampaignReviewStudy, "plan/allowance"),
        (CampaignRefresh, "refresh"),
        (execution, execution_label(execution)),
    ]
    .into_iter()
    .filter_map(|(action, label)| action_hint(app, action, label))
    .collect::<Vec<_>>()
    .join(" · ")
}

fn execution_label(action: ViewHotkeyAction) -> &'static str {
    if action == ViewHotkeyAction::CampaignKill {
        "stop"
    } else {
        "launch"
    }
}

fn action_hint(app: &ShellApp, action: ViewHotkeyAction, label: &str) -> Option<String> {
    if !visible(app, action) {
        return None;
    }
    app.view_keybindings()
        .into_iter()
        .find(|binding| binding.action == action)
        .map(|binding| format!("{} {label}", binding.hint))
}

fn navigate_mode_hint(app: &ShellApp) -> String {
    let keys = app
        .ui()
        .keymap_binding_labels("composer", "navigate_mode", &["Esc"]);
    if keys.is_empty() {
        return "Navigate unbound · configure composer.navigate_mode".into();
    }
    format!(
        "{} Navigate after finishing or clearing the draft",
        keys.join("/")
    )
}

pub(crate) fn campaign_reader_footer(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if !campaign_reader_navigation_owns_input(app) {
        return None;
    }
    let mut bindings = super::footer_keybindings(app);
    let candidates = app
        .view_keybindings()
        .into_iter()
        .map(|binding| (binding.hint, binding.action))
        .collect::<Vec<_>>();
    let mut controls = app
        .ui()
        .keymap_binding_labels("global", "command_palette", &["Ctrl+G"]);
    controls.push(super::interrupt_binding(app).key);
    bindings.sort_by_key(|binding| navigation_priority(binding, &candidates, &controls));
    Some(aliases::compact_aliases(bindings, &candidates))
}

pub(crate) fn campaign_reader_navigation_owns_input(app: &ShellApp) -> bool {
    owns_footer(app) && !reader_editor_open(app) && !reader_attention_open(app)
}

fn reader_editor_open(app: &ShellApp) -> bool {
    app.study_engine_picker().is_some()
        || app.context_generation().is_some()
        || app.study_context_picker().is_some()
        || app.router.campaign().batch_scan_config.is_some()
}

fn reader_attention_open(app: &ShellApp) -> bool {
    app.budget_halt_owns_input()
        || app.advisory().pending_confirm.is_some()
        || super::super::answers_own_input(app)
        || app.guided_scan_question_model().is_some()
}

fn navigation_priority(
    binding: &FooterKeybinding,
    candidates: &[(String, ViewHotkeyAction)],
    controls: &[String],
) -> usize {
    if controls.contains(&binding.key) {
        return 3;
    }
    use ViewHotkeyAction::*;
    let groups: &[&[ViewHotkeyAction]] = &[
        &[CampaignBackToList],
        &[CampaignOpenDetail],
        &[ViewPageDown, ViewPageUp],
        &[],
        &[CampaignCursorPrevious, CampaignCursorNext],
    ];
    groups
        .iter()
        .position(|group| {
            candidates
                .iter()
                .any(|(key, action)| key == &binding.key && group.contains(action))
        })
        .unwrap_or(groups.len())
}

pub(super) fn footer_label(
    app: &ShellApp,
    action: ViewHotkeyAction,
    original: String,
) -> Option<String> {
    if !owns_footer(app) {
        return Some(original);
    }
    visible(app, action).then(|| reading_label(app, action, original))
}

fn owns_footer(app: &ShellApp) -> bool {
    app.shell_view() == ShellView::Campaign && app.input_mode() == InputMode::Navigate
}

fn reading_label(app: &ShellApp, action: ViewHotkeyAction, original: String) -> String {
    use ViewHotkeyAction::*;
    let deck = app.router.campaign();
    if !deck.detail {
        return original;
    }
    match action {
        CampaignOpenDetail => detail_open_label(deck.job_detail).into(),
        CampaignCursorPrevious | CampaignCursorNext => "jobs".into(),
        _ => original,
    }
}

fn detail_open_label(inspecting: bool) -> &'static str {
    if inspecting {
        "read from top"
    } else {
        "inspect job"
    }
}

fn visible(app: &ShellApp, action: ViewHotkeyAction) -> bool {
    use ViewHotkeyAction::*;
    match action {
        CampaignToggleExclude | CampaignCycleWorkers => !fixed_study(app),
        CampaignOpenDetail => can_inspect_selection(app),
        _ => execution_hint_available(app, action),
    }
}

fn can_inspect_selection(app: &ShellApp) -> bool {
    let deck = app.router.campaign();
    if deck.detail {
        deck.selected_job().is_some()
    } else {
        deck.selected_campaign().is_some()
    }
}

fn execution_hint_available(app: &ShellApp, action: ViewHotkeyAction) -> bool {
    use ViewHotkeyAction::*;
    match action {
        CampaignKill => active_dispatcher(app),
        CampaignLaunch => {
            !app.router.campaign().dispatcher_stop_requested
                && !app.selected_fixed_study_has_ended()
        }
        _ => true,
    }
}

fn fixed_study(app: &ShellApp) -> bool {
    app.router
        .campaign()
        .selected_campaign()
        .is_some_and(crate::app::is_fixed_study_snapshot)
}

fn active_dispatcher(app: &ShellApp) -> bool {
    let deck = app.router.campaign();
    deck.dispatcher_pid.is_some() && !deck.dispatcher_stop_requested
}

#[cfg(test)]
mod tests;
