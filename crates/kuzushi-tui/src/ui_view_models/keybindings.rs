mod active;
mod catalog;
mod system;
mod workbench;
mod workflow;
mod workspace;

use super::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FooterKeybinding {
    pub(crate) key: String,
    pub(crate) label: String,
}

pub(crate) fn footer_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.advisory().pending_confirm.is_some() {
        return system::pending_confirm_keybindings(app);
    }
    let mut bindings = active::active_keybindings(app).unwrap_or_else(|| idle_keybindings(app));
    if view_owns_its_input_contract(app) {
        return apply_operator_chrome_overrides(bindings, app);
    }
    bindings = input_mode_bindings(bindings, app.input_mode());
    push_input_mode_binding(&mut bindings, app);
    if app.input_mode() == crate::InputMode::Prompt {
        let tab = bind("Tab", "complete");
        if !bindings.contains(&tab) {
            bindings.insert(after_critical_binding(&bindings), tab);
        }
    }
    apply_operator_chrome_overrides(bindings, app)
}

fn apply_operator_chrome_overrides(
    mut bindings: Vec<FooterKeybinding>,
    app: &ShellApp,
) -> Vec<FooterKeybinding> {
    for (context, action, replaced_key) in [
        ("global", "command_palette", "Ctrl+G"),
        ("global", "help", "help"),
        ("composer", "navigate_mode", "F2"),
        ("composer", "prompt_mode", "Esc"),
        ("composer", "complete", "Tab"),
    ] {
        if !app.ui().keymap_overrides_action(context, action) {
            continue;
        }
        let label = bindings
            .iter()
            .find(|binding| binding.key == replaced_key)
            .map(|binding| binding.label.clone())
            .unwrap_or_else(|| action.replace('_', " "));
        bindings.retain(|binding| binding.key != replaced_key);
        bindings.extend(
            app.ui()
                .keymap_binding_labels(context, action, &[])
                .into_iter()
                .map(|key| FooterKeybinding {
                    key,
                    label: label.clone(),
                }),
        );
    }
    bindings
}

fn view_owns_its_input_contract(app: &ShellApp) -> bool {
    (app.is_picker_view() && !app.picker_prompt_focused())
        || matches!(
            app.shell_view(),
            crate::ShellView::FilePicker
                | crate::ShellView::Setup
                | crate::ShellView::Report
                | crate::ShellView::ConfirmDialog
                | crate::ShellView::QuitConfirm
                | crate::ShellView::Keymap
        )
}

fn input_mode_bindings(
    bindings: Vec<FooterKeybinding>,
    mode: crate::InputMode,
) -> Vec<FooterKeybinding> {
    bindings
        .into_iter()
        .filter_map(|binding| binding_for_mode(binding, mode))
        .collect()
}

fn binding_for_mode(binding: FooterKeybinding, mode: crate::InputMode) -> Option<FooterKeybinding> {
    if is_global_chord(&binding.key) || binding.key == "Shift+Tab" {
        return Some(binding);
    }
    match mode {
        crate::InputMode::Prompt => (typed_command_key(&binding.key)
            || binding.key == "PgUp/PgDn"
            || (binding.key == "Esc" && binding.label == "return to picker"))
            .then_some(binding),
        crate::InputMode::Navigate => navigation_binding_without_false_escape(binding),
    }
}

fn navigation_binding_without_false_escape(binding: FooterKeybinding) -> Option<FooterKeybinding> {
    if typed_command_key(&binding.key) {
        return None;
    }
    match binding.key.as_str() {
        "Esc/q" => Some(bind("q", binding.label)),
        "n/Esc" => Some(bind("n", binding.label)),
        key if key.contains("Esc") => None,
        _ => Some(binding),
    }
}

fn typed_command_key(key: &str) -> bool {
    if key.starts_with('/') || key.starts_with('?') {
        return true;
    }
    !looks_like_physical_key(key)
        && key.chars().count() > 1
        && key.chars().any(|ch| ch.is_ascii_lowercase())
}

fn looks_like_physical_key(key: &str) -> bool {
    key.chars().count() == 1
        || key.contains('/')
        || key.contains('+')
        || matches!(
            key,
            "Tab"
                | "Shift+Tab"
                | "Enter"
                | "Esc"
                | "Space"
                | "Backspace"
                | "PgUp"
                | "PgDn"
                | "PgUp/PgDn"
                | "Up"
                | "Down"
                | "KEYS"
                | "COMMAND"
        )
}

fn is_global_chord(key: &str) -> bool {
    key.starts_with("Ctrl+")
}

fn push_input_mode_binding(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    let binding = match app.input_mode() {
        crate::InputMode::Prompt => bind("F2", "nav mode"),
        crate::InputMode::Navigate => bind("Esc", "prompt"),
    };
    if !bindings.contains(&binding) {
        bindings.insert(after_critical_binding(bindings), binding);
    }
}

fn after_critical_binding(bindings: &[FooterKeybinding]) -> usize {
    usize::from(bindings.first().is_some_and(|binding| {
        binding.key == "Ctrl+C"
            && matches!(binding.label.as_str(), "request abort" | "wait cleanup")
    }))
}

fn idle_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let specialized = catalog::keybindings(app)
        .or_else(|| workbench::keybindings(app))
        .or_else(|| workflow::keybindings(app))
        .or_else(|| workspace::keybindings(app))
        .or_else(|| system::keybindings(app));
    let uses_default = specialized.is_none();
    let mut bindings = specialized.unwrap_or_else(default_keybindings);
    if matches!(app.shell_view(), crate::ShellView::PlanningPicker) {
        return bindings;
    }
    if uses_default && !view_owns_its_input_contract(app) {
        push_view_keybindings(&mut bindings, app);
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

pub(super) fn bind(key: impl Into<String>, label: impl Into<String>) -> FooterKeybinding {
    FooterKeybinding {
        key: key.into(),
        label: label.into(),
    }
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
        bind("Ctrl+G", "palette"),
        bind("help", "command list"),
        bind("Ctrl+C", "exit"),
    ]
}

#[cfg(test)]
mod tests;
