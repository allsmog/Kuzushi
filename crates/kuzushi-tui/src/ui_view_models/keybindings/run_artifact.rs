use super::{bind, interrupt_binding, reader_escape_label, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if !is_artifact_reader(app) {
        return None;
    }
    let mut bindings = vec![
        bind("Esc", reader_escape_label(app)),
        bind("PgUp/PgDn", "scroll"),
        interrupt_binding(app),
    ];
    if app.shell_view() == ShellView::RunDiff {
        bindings.insert(1, bind("Tab", "findings / sources"));
    }
    if crate::ui_view_models::answers_available(app) && app.agent_chat().is_some() {
        bindings.push(bind("Ctrl+T", "answers"));
    }
    Some(bindings)
}

fn is_artifact_reader(app: &ShellApp) -> bool {
    match app.shell_view() {
        ShellView::Replay | ShellView::Trace => true,
        ShellView::RunDiff => app.input().is_empty(),
        _ => false,
    }
}
