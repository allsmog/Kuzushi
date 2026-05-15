use super::*;

pub(in crate::renderer::chrome::footer::keybindings) fn catalog_keybindings(
    app: &ShellApp,
) -> Option<Vec<(&'static str, &'static str)>> {
    let bindings = match app.shell_view {
        ShellView::Home => vec![
            ("modules", "browse"),
            ("recommend", "plan"),
            ("scan", "scan target"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Catalog if !app.catalog_expanded => vec![
            ("modules", "browse"),
            ("use <id>", "focus module"),
            ("scan", "scan target"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Catalog => vec![
            ("j/k", "row"),
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("findings", "findings"),
            ("?", "help"),
        ],
        ShellView::Recommend => vec![
            ("run <tool>", "dispatch"),
            ("runs", "ledger"),
            ("back", "home"),
            ("?", "help"),
        ],
        _ => return None,
    };
    Some(bindings)
}

pub(in crate::renderer::chrome::footer::keybindings) fn finding_keybindings(
    app: &ShellApp,
) -> Option<Vec<(&'static str, &'static str)>> {
    let bindings = match app.shell_view {
        ShellView::Findings => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([("scan", "rescan"), ("back", "home"), ("Ctrl+C", "exit")]);
            bindings
        }
        ShellView::Finding => vec![
            ("back", "findings"),
            ("findings", "list"),
            ("scan", "rescan"),
            ("Ctrl+C", "exit"),
        ],
        _ => return None,
    };
    Some(bindings)
}
