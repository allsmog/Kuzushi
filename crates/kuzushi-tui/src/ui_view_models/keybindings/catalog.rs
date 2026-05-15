use super::{bind, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::Home => Some(home_keybindings()),
        ShellView::Catalog if !app.catalog_expanded => Some(collapsed_catalog_keybindings()),
        ShellView::Catalog => Some(expanded_catalog_keybindings()),
        ShellView::Recommend => Some(recommend_keybindings()),
        _ => None,
    }
}

fn home_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("modules", "browse"),
        bind("recommend", "plan"),
        bind("scan", "scan target"),
        bind("Ctrl+C", "exit"),
    ]
}

fn collapsed_catalog_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("modules", "browse"),
        bind("use <id>", "focus module"),
        bind("scan", "scan target"),
        bind("Ctrl+C", "exit"),
    ]
}

fn expanded_catalog_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("j/k", "row"),
        bind("PgUp/PgDn", "scroll"),
        bind("use <id>", "focus module"),
        bind("findings", "findings"),
        bind("?", "help"),
    ]
}

fn recommend_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("run <tool>", "dispatch"),
        bind("runs", "ledger"),
        bind("back", "home"),
        bind("?", "help"),
    ]
}
