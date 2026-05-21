use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::Threat(_) => Some(threat_keybindings(app)),
        ShellView::ModuleRun => Some(module_run_keybindings(app)),
        ShellView::PromptsEditor => Some(prompts_editor_keybindings()),
        ShellView::AgentChat => Some(agent_chat_keybindings()),
        _ => None,
    }
}

fn threat_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("threats edit", "edit threats"),
        bind("back", "home"),
        bind("Ctrl+C", "exit"),
    ]);
    bindings
}

fn module_run_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("findings", "list"),
        bind("back", "home"),
        bind("Ctrl+C", "exit"),
    ]);
    bindings
}

fn prompts_editor_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("prompt edit", "open editor"),
        bind("prompt show", "view contents"),
        bind("back", "module"),
        bind("Ctrl+C", "exit"),
    ]
}

fn agent_chat_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("ask <q>", "new question (?text is the shorthand)"),
        bind("model", "runtime"),
        bind("back", "home"),
    ]
}
