use super::{bind, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::Home => Some(home_keybindings()),
        ShellView::Catalog if !app.catalog_route.is_expanded() => {
            Some(collapsed_catalog_keybindings())
        }
        ShellView::Catalog => Some(expanded_catalog_keybindings()),
        ShellView::Recommend => Some(recommend_keybindings()),
        _ => None,
    }
}

fn home_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("n", "next phase"),
        bind("modules", "browse"),
        bind("options sast:scan", "tune scan"),
        bind("scan", "run scanners"),
        bind("Ctrl+C", "exit"),
    ]
}

fn collapsed_catalog_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("modules", "browse"),
        bind("use <id>", "focus module"),
        bind("scan", "run scanners"),
        bind("Ctrl+C", "exit"),
    ]
}

fn expanded_catalog_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("j/k", "row"),
        bind("PgUp/PgDn", "scroll"),
        bind("Enter", "use selected row"),
        bind("use <id>", "focus module"),
        bind("findings", "list"),
        bind("?", "help"),
    ]
}

fn recommend_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Ctrl+G", "palette"),
        bind("j/k", "component"),
        bind("Enter", "scan focused"),
        bind("p", "promote target"),
        bind("runs", "ledger"),
        bind("Esc", "back"),
        bind("?", "help"),
    ]
}
