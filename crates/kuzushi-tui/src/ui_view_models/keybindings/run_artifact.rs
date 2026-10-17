use super::{bind, interrupt_binding, reader_escape_label, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if !is_artifact_reader(app) {
        return None;
    }
    let mut bindings = vec![
        bind("Esc", reader_escape_label(app)),
        bind("PgUp/PgDn", "scroll"),
        bind("Home/End", "start/end"),
        interrupt_binding(app),
    ];
    if let Some(binding) = artifact_reading_binding(app) {
        bindings.insert(1, binding);
    }
    bindings.extend(replay_refresh_binding(app));
    if crate::ui_view_models::answers_available(app) && app.agent_chat().is_some() {
        bindings.push(bind("Ctrl+T", "answers"));
    }
    Some(bindings)
}

fn replay_refresh_binding(app: &ShellApp) -> Option<FooterKeybinding> {
    (app.shell_view() == ShellView::Replay && super::super::replay_switch_owns_input(app))
        .then(|| bind("r", "refresh limits"))
}

fn artifact_reading_binding(app: &ShellApp) -> Option<FooterKeybinding> {
    match app.shell_view() {
        ShellView::RunDiff => Some(bind("Tab", "findings / sources")),
        ShellView::Replay => replay_reading_binding(app),
        _ => None,
    }
}

fn replay_reading_binding(app: &ShellApp) -> Option<FooterKeybinding> {
    if app.shell_view() != ShellView::Replay || !super::super::replay_has_summary(app) {
        return None;
    }
    if !super::super::replay_switch_owns_input(app) {
        return None;
    }
    let label = super::super::replay_next_label(app);
    Some(bind("Tab", label))
}

fn is_artifact_reader(app: &ShellApp) -> bool {
    match app.shell_view() {
        ShellView::Replay | ShellView::Trace => true,
        ShellView::RunDiff => app.input().is_empty(),
        _ => false,
    }
}
