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
        bind("back", "home"),
        bind("Ctrl+C", "exit"),
    ]);
    bindings
}

fn finding_detail_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("back", "findings"),
        bind("findings", "list"),
        bind("scan", "rescan"),
        bind("Ctrl+C", "exit"),
    ]
}
