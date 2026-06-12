use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::Findings => Some(findings_keybindings(app)),
        ShellView::Finding => Some(finding_detail_keybindings()),
        _ => None,
    }
}

fn findings_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("scan", "rescan"),
        bind("Esc", "home"),
        bind("Ctrl+C", "exit"),
    ]);
    bindings
}

fn finding_detail_keybindings() -> Vec<FooterKeybinding> {
    // Esc is the key that actually returns to the list — advertising the
    // typed `findings` verb as if it were a key misled operators.
    vec![
        bind("Esc", "back to list"),
        bind("scan", "rescan"),
        bind("Ctrl+C", "exit"),
    ]
}
