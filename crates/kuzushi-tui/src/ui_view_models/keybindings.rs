mod active;
mod catalog;
mod finding;
mod system;
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
    let tab = bind("Tab", "complete");
    if !bindings.contains(&tab) {
        bindings.insert(0, tab);
    }
    bindings
}

fn idle_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    catalog::keybindings(app)
        .or_else(|| finding::keybindings(app))
        .or_else(|| workflow::keybindings(app))
        .or_else(|| workspace::keybindings(app))
        .or_else(|| system::keybindings(app))
        .unwrap_or_else(default_keybindings)
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

fn default_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Enter", "run command"),
        bind("Ctrl+G", "palette"),
        bind("help", "command list"),
        bind("Ctrl+C", "exit"),
    ]
}

#[cfg(test)]
mod tests;
