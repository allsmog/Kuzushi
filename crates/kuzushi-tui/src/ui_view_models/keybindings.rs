mod active;
mod catalog;
mod system;
mod workbench;
mod workflow;
mod workspace;

use super::ShellApp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FooterKeybinding {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
}

pub(crate) fn footer_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if let Some(bindings) = active::active_keybindings(app) {
        return bindings;
    }
    let mut bindings = idle_keybindings(app);
    push_input_mode_binding(&mut bindings, app);
    // Modal pickers swallow Tab while their list/options controls own focus.
    // Once the operator explicitly focuses the prompt with `:`, Tab is command
    // completion again.
    if app.input_mode() == crate::InputMode::Prompt
        && (!app.is_picker_view() || app.picker_prompt_focused())
    {
        let tab = bind("Tab", "complete");
        if !bindings.contains(&tab) {
            bindings.insert(0, tab);
        }
    }
    bindings
}

fn push_input_mode_binding(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    let binding = match app.input_mode() {
        crate::InputMode::Prompt => bind("F2", "nav mode"),
        crate::InputMode::Navigate => bind("Esc", "prompt"),
    };
    if !bindings.contains(&binding) {
        bindings.insert(0, binding);
    }
}

fn idle_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = catalog::keybindings(app)
        .or_else(|| workbench::keybindings(app))
        .or_else(|| workflow::keybindings(app))
        .or_else(|| workspace::keybindings(app))
        .or_else(|| system::keybindings(app))
        .unwrap_or_else(default_keybindings);
    if matches!(app.shell_view(), crate::ShellView::PlanningPicker) {
        return bindings;
    }
    push_unique_binding(&mut bindings, bind("workbench", "command center"));
    bindings
}

pub(super) fn push_view_keybindings(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    for binding in app.view_keybindings() {
        let candidate = bind(binding.hint, binding.label);
        if !bindings.contains(&candidate) {
            bindings.push(candidate);
        }
    }
}

pub(super) fn bind(key: &'static str, label: &'static str) -> FooterKeybinding {
    FooterKeybinding { key, label }
}

fn push_unique_binding(bindings: &mut Vec<FooterKeybinding>, binding: FooterKeybinding) {
    if !bindings.contains(&binding) {
        bindings.push(binding);
    }
}

fn default_keybindings() -> Vec<FooterKeybinding> {
    // Every unmapped view gets the exit path first — a leaf view (auth,
    // cost, patch, failure-handoff, …) must never read as a dead-end.
    vec![
        bind("Esc", "back"),
        bind("workbench", "command center"),
        bind("Enter", "run command"),
        bind("Ctrl+G", "palette"),
        bind("help", "command list"),
        bind("Ctrl+C", "exit"),
    ]
}

#[cfg(test)]
mod tests;
