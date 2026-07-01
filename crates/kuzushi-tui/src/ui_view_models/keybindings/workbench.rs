use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    matches!(app.shell_view, ShellView::Workbench).then(|| workbench_keybindings(app))
}

fn workbench_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    // Lead with the view's own pane navigation (Tab / j/k / Enter), then the
    // standing run + exit affordances so the command center never reads as a
    // dead end.
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("scan", "rescan"),
        bind("Esc", "back"),
        bind("Ctrl+C", "exit"),
    ]);
    bindings
}
