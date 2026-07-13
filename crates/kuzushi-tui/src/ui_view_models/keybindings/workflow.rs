use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view() {
        ShellView::Threat => Some(threat_keybindings(app)),
        ShellView::ModuleRun => Some(module_run_keybindings(app)),
        ShellView::PromptsEditor => Some(prompts_editor_keybindings(app)),
        ShellView::AgentChat => Some(agent_chat_keybindings(app)),
        ShellView::Activity => Some(activity_keybindings(app)),
        _ => None,
    }
}

fn activity_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("scan", "start scan"),
        bind("run <tool>", "launch tool"),
        bind("jobs", "run control"),
    ]);
    bindings
}

fn threat_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([bind("threats edit", "edit threats"), bind("Ctrl+C", "exit")]);
    bindings
}

fn module_run_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([bind("findings", "list"), bind("Ctrl+C", "exit")]);
    bindings
}

fn prompts_editor_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("prompt edit", "open editor"),
        bind("prompt show", "view contents"),
        bind("Ctrl+C", "exit"),
    ]);
    bindings
}

fn agent_chat_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.extend([
        bind("ask <q>", "new question (?text is the shorthand)"),
        bind("model", "runtime"),
    ]);
    bindings
}
