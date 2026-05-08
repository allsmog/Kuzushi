use super::*;

pub(in crate::renderer::chrome::footer::keybindings) fn workspace_keybindings(
    app: &ShellApp,
) -> Option<Vec<(&'static str, &'static str)>> {
    let bindings = match app.shell_view {
        ShellView::Options(_) => vec![
            ("set key value", "set"),
            ("show advanced", "advanced"),
            ("show missing", "missing"),
            ("back", "module"),
        ],
        ShellView::Context => vec![
            ("context build", "build"),
            ("context status", "status"),
            ("context regen repo", "regen"),
            ("back", "module"),
        ],
        ShellView::Workspace => vec![
            ("workspace status", "status"),
            ("workspace export", "findings"),
            ("scan <target>", "select target"),
            ("back", "module"),
        ],
        ShellView::KnowledgeBase => vec![
            ("PgUp/PgDn", "scroll"),
            ("attach <path>", "attach"),
            ("detach <id>", "detach"),
            ("reparse <id>", "reparse"),
        ],
        _ => return None,
    };
    Some(bindings)
}
