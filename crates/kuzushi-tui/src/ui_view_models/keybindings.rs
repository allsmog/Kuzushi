mod active;
mod catalog;
mod lessons;
mod relationships;
mod run_artifact;
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

pub(super) fn interrupt_binding(app: &ShellApp) -> FooterKeybinding {
    active::active_keybindings(app)
        .and_then(|bindings| bindings.into_iter().find(|binding| binding.key == "Ctrl+C"))
        .unwrap_or_else(|| bind("Ctrl+C", "exit"))
}

pub(super) fn reader_escape_label(app: &ShellApp) -> &'static str {
    if app.notice_captures_escape() {
        "dismiss notice"
    } else {
        "back"
    }
}

pub(crate) fn footer_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if let Some(bindings) = owned_input_bindings(app) {
        return bindings;
    }
    let mut bindings = active::active_keybindings(app).unwrap_or_else(|| idle_keybindings(app));
    if view_owns_its_input_contract(app) {
        return apply_operator_chrome_overrides(bindings, app);
    }
    bindings = input_mode_bindings(bindings, app.input_mode());
    push_input_mode_binding(&mut bindings, app);
    insert_prompt_completion_binding(&mut bindings, app);
    push_paste_inspection_binding(&mut bindings, app);
    if super::answers_available(app) && app.agent_chat().is_some() {
        bindings.insert(0, bind("Ctrl+T", "answers"));
    }
    prioritize_reader_paging(&mut bindings, app);
    apply_operator_chrome_overrides(bindings, app)
}

fn push_paste_inspection_binding(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    if app.input_mode() == crate::InputMode::Prompt && app.editor().has_pasted_blocks() {
        bindings.push(bind("Ctrl+Y", "inspect paste · Ctrl+_ undo"));
    }
}

fn prioritize_reader_paging(bindings: &mut [FooterKeybinding], app: &ShellApp) {
    if app.shell_view() != crate::ShellView::Workbench {
        return;
    }
    if !focused_reader_needs_paging(app) {
        return;
    }
    bindings.sort_by_key(|binding| u8::from(binding.key != "PgUp/PgDn"));
}

fn focused_reader_needs_paging(app: &ShellApp) -> bool {
    let page = super::active_workbench_page(app);
    if page == crate::app::WorkbenchPage::Review {
        return app.router.workbench().focus_for(page) == super::PhaseSurfaceId::ReviewDetail;
    }
    app.current_map_viz_page() == crate::scene3d::VizPage::EntryPoints
        && workbench::ready_map_gallery_is_visible(app)
}

fn owned_input_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.advisory().pending_confirm.is_some() {
        return Some(system::pending_confirm_keybindings(app));
    }
    batch_config_bindings(app)
        .or_else(|| relationships::owned_bindings(app))
        .or_else(|| lessons::owned_bindings(app))
        .or_else(|| catalog::owned_picker_keybindings(app))
        .or_else(|| super::answers_own_input(app).then(|| answer_bindings(app)))
        .or_else(|| workbench::prove_detail_bindings(app))
        .or_else(|| run_artifact::keybindings(app))
}

fn answer_bindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = answer_editing_bindings(app);
    if let Some(chat) = app.agent_chat().filter(|chat| chat.running) {
        let label = if chat.abort_requested {
            "canceling Ask"
        } else {
            "cancel Ask"
        };
        bindings.insert(0, bind("Ctrl+C", label));
    }
    bindings
}

fn answer_editing_bindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.router.answers().focus == crate::app::AnswerFocus::Reply {
        return vec![
            bind("Enter", "ask"),
            bind("Shift+Enter", "newline"),
            bind("Esc", "keep draft"),
            bind("Ctrl+T", "workspace"),
        ];
    }
    vec![
        bind("↑/↓", "scroll answer"),
        bind("Enter", "reply"),
        bind("Alt+←/→", "contexts"),
        bind("Ctrl+T", "workspace"),
    ]
}

fn batch_config_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.batch_number_editor_open() {
        return Some(vec![
            bind("Enter", "save value"),
            bind("Esc", "cancel edit"),
        ]);
    }
    app.batch_config_open().then(|| {
        vec![
            bind("↑/↓", "setting"),
            bind("Enter", "edit"),
            bind("L", "review/launch"),
            bind("Esc", "campaigns"),
        ]
    })
}

fn insert_prompt_completion_binding(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    if app.input_mode() != crate::InputMode::Prompt {
        return;
    }
    let tab = bind("Tab", prompt_tab_action(app));
    if !bindings.contains(&tab) {
        bindings.insert(after_critical_binding(bindings), tab);
    }
}

fn prompt_tab_action(app: &ShellApp) -> &'static str {
    if !app.input().is_empty() {
        return "complete";
    }
    if app.shell_view() == crate::ShellView::RunDiff {
        return "findings / sources";
    }
    if app.shell_view() == crate::ShellView::Workbench
        && workbench::ready_map_gallery_is_visible(app)
    {
        "map view"
    } else {
        "complete"
    }
}

fn apply_operator_chrome_overrides(
    mut bindings: Vec<FooterKeybinding>,
    app: &ShellApp,
) -> Vec<FooterKeybinding> {
    for (context, action, replaced_key) in [
        ("global", "command_palette", "Ctrl+G"),
        ("global", "help", "help"),
        ("composer", "navigate_mode", "Esc"),
        ("composer", "prompt_mode", "Esc"),
        ("composer", "complete", "Tab"),
    ] {
        if !chrome_override_applies(app, context, action) {
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

fn chrome_override_applies(app: &ShellApp, context: &str, action: &str) -> bool {
    if action == "complete" && prompt_tab_action(app) != "complete" {
        return false;
    }
    app.ui().keymap_overrides_action(context, action)
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
                | crate::ShellView::Scene
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
        // A warning/error notice takes the next Esc before any mode flip, so
        // the footer must not promise the flip that press will not perform.
        _ if app.notice_captures_escape() => bind("Esc", "dismiss notice"),
        crate::InputMode::Prompt => bind("Esc", prompt_navigate_label(app)),
        crate::InputMode::Navigate => bind("Esc", "prompt"),
    };
    if !bindings.contains(&binding) {
        bindings.insert(after_critical_binding(bindings), binding);
    }
}

/// On the Review page the whole findings flow lives behind Navigate mode
/// (j/k selects, Enter opens detail), but Prompt mode filters those physical
/// keys out of the footer. Name the flow on the doorway itself so the footer
/// still gives direction instead of a bare "nav mode".
fn prompt_navigate_label(app: &ShellApp) -> String {
    if let Some(label) = prompt_editor_escape_label(app) {
        return label;
    }
    if map_summary_navigation_available(app) {
        return "nav components · j/k move · Enter DFD".to_string();
    }
    let review_flow_available = app.shell_view() == crate::ShellView::Workbench
        && super::active_workbench_page(app) == crate::app::WorkbenchPage::Review
        && super::visible_findings_len(app) > 0;
    if review_flow_available {
        "nav findings · j/k move · Enter detail".to_string()
    } else {
        "nav mode".to_string()
    }
}

fn prompt_editor_escape_label(app: &ShellApp) -> Option<String> {
    if app.completion_cycle().is_some() {
        return Some("restore completion prefix".to_string());
    }
    (!app.input().is_empty()).then(|| "clear draft · Ctrl+_ restores".to_string())
}

fn map_summary_navigation_available(app: &ShellApp) -> bool {
    app.shell_view() == crate::ShellView::Workbench
        && super::active_workbench_page(app) == crate::app::WorkbenchPage::Map
        && super::map_gallery_is_primary(app)
        && app.current_map_viz_page() == crate::scene3d::VizPage::Summary
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
    push_unique_binding(&mut bindings, bind("workbench", "phase workflow"));
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
        bind("workbench", "phase workflow"),
        bind("Ctrl+G", "palette"),
        bind("help", "command list"),
        bind("Ctrl+C", "exit"),
    ]
}

#[cfg(test)]
mod tests;
