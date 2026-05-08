use super::*;

pub(in crate::renderer::chrome::footer::keybindings) fn workflow_keybindings(
    app: &ShellApp,
) -> Option<Vec<(&'static str, &'static str)>> {
    let bindings = match app.shell_view {
        ShellView::Threat(_) => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([
                ("threats edit", "edit"),
                ("back", "home"),
                ("Ctrl+C", "exit"),
            ]);
            bindings
        }
        ShellView::ModuleRun => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([("findings", "list"), ("back", "home"), ("Ctrl+C", "exit")]);
            bindings
        }
        ShellView::PromptsEditor => vec![
            ("prompt edit", "edit"),
            ("prompt show", "show"),
            ("back", "module"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::AgentChat => vec![
            ("ask <q>", "new question"),
            ("?text", "ask"),
            ("model", "runtime"),
            ("back", "home"),
        ],
        _ => return None,
    };
    Some(bindings)
}
