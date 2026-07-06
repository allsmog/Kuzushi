use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    matches!(app.shell_view, ShellView::Workbench).then(|| workbench_keybindings(app))
}

fn workbench_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    // Lead with the view's own pane navigation (Tab / j/k / Enter), then the
    // standing run + exit affordances so the command center never reads as a
    // dead end.
    let mut bindings = vec![bind("Enter", "open finding")];
    push_view_keybindings(&mut bindings, app);
    bindings.extend([bind("Ctrl+G", "palette"), bind("scan", "run scan")]);
    if !app.findings.is_empty() {
        bindings.push(bind(WORKBENCH_REPORT_COMMAND, "export report"));
    }
    bindings.push(bind("Ctrl+C", "exit"));
    bindings
}
