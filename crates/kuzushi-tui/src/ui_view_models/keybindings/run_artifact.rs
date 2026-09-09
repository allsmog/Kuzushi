use super::{bind, interrupt_binding, reader_escape_label, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if !matches!(app.shell_view(), ShellView::Replay | ShellView::Trace) {
        return None;
    }
    let mut bindings = vec![
        bind("Esc", reader_escape_label(app)),
        bind("PgUp/PgDn", "scroll"),
        interrupt_binding(app),
    ];
    if crate::ui_view_models::answers_available(app) && app.agent_chat().is_some() {
        bindings.push(bind("Ctrl+T", "answers"));
    }
    Some(bindings)
}
