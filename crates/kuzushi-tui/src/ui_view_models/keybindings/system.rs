use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view() {
        ShellView::History => Some(history_keybindings(app)),
        ShellView::Story => Some(story_keybindings(app)),
        ShellView::Help => Some(help_keybindings(app)),
        ShellView::Permissions => Some(permission_policy_keybindings(app)),
        ShellView::Health => Some(health_keybindings(app)),
        ShellView::BootSplash => Some(boot_splash_keybindings()),
        ShellView::QuitConfirm => Some(quit_confirm_keybindings(app.has_running_work())),
        ShellView::ConfirmDialog => Some(pending_confirm_keybindings(app)),
        ShellView::ThemePicker => Some(theme_picker_keybindings()),
        ShellView::Keymap => Some(keymap_keybindings()),
        ShellView::UpdateAvailable => Some(update_available_keybindings()),
        ShellView::Interruption => Some(interruption_keybindings(app)),
        ShellView::Tools => Some(tools_keybindings(app)),
        ShellView::Config => Some(config_keybindings(app)),
        ShellView::Scene => Some(scene_keybindings(app)),
        ShellView::SastTasks => Some(sast_tasks_keybindings(app)),
        // First-run pickers own input — surface their controls in the footer
        // so the modal has one canonical hint row.
        ShellView::PlanningPicker => Some(planning_picker_keybindings(app)),
        ShellView::Setup => Some(setup_keybindings(app)),
        ShellView::Report => Some(report_keybindings(app)),
        ShellView::FilePicker => Some(file_picker_keybindings(app)),
        ShellView::TargetPicker => Some(choice_picker_keybindings(app)),
        _ => None,
    }
}

fn config_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = vec![bind("Enter", "choose model")];
    push_view_keybindings(&mut bindings, app);
    bindings
}

fn report_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.router.report().editing_path() {
        return vec![
            bind("Esc", "cancel"),
            bind("Enter/Ctrl+S", "save path"),
            bind("←/→", "cursor"),
            bind("Delete/⌫", "delete"),
        ];
    }
    vec![
        bind("Esc/q", "return"),
        bind("Enter", "export/retry"),
        bind("PgUp/PgDn", "read"),
        bind("j/k", "format"),
        bind("c", "completeness"),
        bind("e", "edit path"),
        bind("o", "reveal"),
    ]
}

fn setup_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.router.setup().editor() == Some(crate::app::SetupEditor::Plan) {
        return planning_picker_keybindings(app);
    }
    if matches!(
        app.router.setup().editor(),
        Some(crate::app::SetupEditor::Model | crate::app::SetupEditor::Credentials)
    ) {
        return choice_picker_keybindings(app);
    }
    if let Some(bindings) = setup_value_editor_keybindings(app) {
        return bindings;
    }
    vec![
        bind("↑/↓", "move"),
        bind("type", "command"),
        bind("Enter", "open/start"),
        bind("Esc", "workbench"),
        bind("Ctrl+C", "exit"),
    ]
}

fn setup_value_editor_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.router.setup().editor() == Some(crate::app::SetupEditor::ThreatModel) {
        return Some(map_run_config_keybindings(app));
    }
    (app.router.setup().editor() == Some(crate::app::SetupEditor::Budget)).then(|| {
        vec![
            bind("type", "budget USD"),
            bind("←/→", "cursor"),
            bind("Home/End", "ends"),
            bind("Delete", "delete ahead"),
            bind("Ctrl+U", "clear to start"),
            bind("Enter", "save"),
            bind("Esc", "cancel"),
        ]
    })
}

fn map_run_config_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.map_scope_picker_open() {
        return vec![
            bind("type", "filter scopes"),
            bind("↑/↓", "scope"),
            bind("Enter", "select"),
            bind("Esc", "cancel"),
        ];
    }
    if let Some(list) = app.router.setup().map_run_config().text() {
        if list.field.is_none() {
            return vec![
                bind("↑/↓", "entry"),
                bind("Enter", "edit"),
                bind("a", "add"),
                bind("Delete", "remove"),
                bind("Esc", "back"),
            ];
        }
        let document = list.row == crate::app::MapRunConfigRowId::DesignDocs;
        return vec![
            bind("←/→/Home/End", "cursor"),
            bind("Enter", if document { "save" } else { "new line" }),
            bind("Ctrl+S", "save"),
            bind("Esc", "cancel"),
        ];
    }
    vec![
        bind("j/k/↑/↓", "row"),
        bind("Enter/Space", "cycle/edit"),
        bind("Esc", "return to Setup"),
    ]
}

fn permission_policy_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("doctor", "preflight"));
    bindings.push(bind("config", "model/runtime"));
    bindings.push(bind("runs", "execution evidence"));
    bindings
}

fn planning_picker_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.engagement.planning_picker().option_edit().is_some() {
        return vec![
            bind("←/→ ↑/↓", "cursor"),
            bind("Delete", "delete ahead"),
            bind("Ctrl+U", "clear to start"),
            bind("Shift+Enter", "new line"),
            bind("Enter/Ctrl+S", "save"),
            bind("PgUp/PgDn", "error details"),
            bind("Esc", "cancel"),
        ];
    }
    match app.engagement.planning_picker().focus() {
        crate::app::PickerFocus::Prompt => picker_prompt_keybindings(),
        crate::app::PickerFocus::OptionsPane
            if app.engagement.planning_picker().returns_to_setup() =>
        {
            vec![
                bind("KEYS", "↑/↓ option"),
                bind("Tab/Shift+Tab", "tasks"),
                bind("type", "command"),
                bind("Enter", "edit"),
                bind("Space", "cycle"),
                bind("Ctrl+S", "persist option"),
                bind("Esc", "tasks"),
            ]
        }
        crate::app::PickerFocus::OptionsPane => vec![
            bind("KEYS", "↑/↓ option"),
            bind("Tab/Shift+Tab", "steps"),
            bind("type", "command"),
            bind("Enter", "edit"),
            bind("Space", "cycle"),
            bind("Ctrl+S", "persist option"),
            bind("Esc", "steps"),
        ],
        crate::app::PickerFocus::List => planning_picker_list_keybindings(app),
    }
}

fn planning_picker_list_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.engagement.planning_picker().returns_to_setup() {
        return setup_plan_keybindings();
    }
    let inline_selected = planning_inline_action_selected(app);
    let mut bindings = vec![
        bind("KEYS", "↑/↓ move"),
        bind("←/→", "phase"),
        bind("type", "command"),
    ];
    match inline_selected {
        Some(true) => {
            bindings.push(bind("Space", "uncheck attach"));
            bindings.push(bind("Enter", "attach file"));
        }
        Some(false) => {
            bindings.push(bind("Space", "select attach"));
            bindings.push(bind("Enter", "run checked"));
        }
        None => {
            bindings.push(bind("Tab/Shift+Tab", "focus pane"));
            bindings.push(bind("Space", "cycle outcome"));
            bindings.push(bind("Enter", "run checked"));
        }
    }
    bindings.push(bind("Esc", "workbench"));
    bindings
}

fn setup_plan_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("KEYS", "↑/↓ move"),
        bind("type", "command"),
        bind("Space", "cycle outcome"),
        bind("Tab/Shift+Tab", "focus pane"),
        bind("Enter", "save to Setup"),
        bind("Esc", "return to Setup"),
    ]
}

fn planning_inline_action_selected(app: &ShellApp) -> Option<bool> {
    app.engagement
        .planning_picker()
        .current_row()
        .filter(|row| row.id.is_inline_action())
        .map(|row| {
            app.engagement
                .planning_picker()
                .selected()
                .contains(&row.id)
        })
}

fn choice_picker_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if choice_picker_prompt_focused(app) {
        return picker_prompt_keybindings();
    }
    if app.router.setup().editor() == Some(crate::app::SetupEditor::Credentials)
        && app.router.auth_picker().is_api_key_row()
    {
        return vec![
            bind("type", "API key"),
            bind("Enter", "accept"),
            bind("Esc", "back"),
        ];
    }
    vec![
        bind("↑/↓", "move"),
        bind("demo", "offline"),
        bind("type", "command"),
        bind("Enter", "select"),
        bind("Esc", choice_picker_escape_hint(app)),
    ]
}

fn choice_picker_escape_hint(app: &ShellApp) -> &'static str {
    if app.router.setup().editor() == Some(crate::app::SetupEditor::Model) {
        "keep current"
    } else {
        "skip"
    }
}

fn choice_picker_prompt_focused(app: &ShellApp) -> bool {
    match (app.shell_view(), app.router.setup().editor()) {
        (ShellView::Setup, Some(crate::app::SetupEditor::Model)) => {
            app.router.model_picker().focus() == crate::app::PickerFocus::Prompt
        }
        (ShellView::Setup, Some(crate::app::SetupEditor::Credentials)) => {
            app.router.auth_picker().focus() == crate::app::PickerFocus::Prompt
        }
        (ShellView::TargetPicker, _) => {
            app.router.target_picker().focus() == crate::app::PickerFocus::Prompt
        }
        _ => false,
    }
}

fn picker_prompt_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Esc", "return to picker"),
        bind("Enter", "run command"),
        bind("Ctrl+G", "palette"),
        bind("Ctrl+C", "exit"),
    ]
}

fn file_picker_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let document = app.router.file_picker().purpose() == crate::app::FilePickerPurpose::MapDocument;
    vec![
        bind("type", "filter"),
        bind("↑/↓", "move"),
        bind("Enter", if document { "choose" } else { "attach" }),
        bind("Esc", "close"),
    ]
}

fn boot_splash_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("?", "help"),
        bind("catalog", "modules"),
        bind("doctor", "health"),
        bind("Esc", "back"),
    ]
}

fn quit_confirm_keybindings(has_running_work: bool) -> Vec<FooterKeybinding> {
    let exit_label = if has_running_work {
        "cancel if needed + exit"
    } else {
        "exit"
    };
    vec![bind("y/Y", exit_label), bind("n/N/Esc", "stay")]
}

pub(super) fn pending_confirm_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if !crate::app::allowance::approval_visible(app) {
        return vec![bind("Esc", "cancel allowance approval")];
    }
    let Some(confirm) = app.advisory().pending_confirm.as_ref() else {
        return vec![bind("Esc", "back"), bind("Ctrl+C", "quit")];
    };
    if !confirm.kind.allows_yes() {
        return vec![
            bind("n/Esc", "close refusal"),
            bind("N", "deny for session"),
            bind("Ctrl+C", "quit"),
        ];
    }
    let mut bindings = vec![bind("y", "allow once")];
    if confirm.kind.allows_remembered_yes() {
        bindings.push(bind("Y", "allow for session"));
    }
    bindings.extend([
        bind("n/Esc", "deny once"),
        bind("N", "deny for session"),
        bind("Ctrl+C", "quit"),
    ]);
    bindings
}

fn theme_picker_keybindings() -> Vec<FooterKeybinding> {
    vec![bind("theme <name>", "apply"), bind("Esc", "close")]
}

fn keymap_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("j/k/↑/↓", "scroll"),
        bind("g/G", "ends"),
        bind("PgUp/PgDn", "scroll"),
        bind("Esc/q", "close"),
    ]
}

fn update_available_keybindings() -> Vec<FooterKeybinding> {
    vec![bind("/update", "pull"), bind("/changelog", "notes")]
}

fn interruption_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("doctor", "preflight"));
    bindings.push(bind("auth", "credentials"));
    bindings.push(bind("config", "policy"));
    bindings
}

// The security-viz gallery is fully interactive but its controls live only in
// the key handler; surface them so Tab/orbit/pause are discoverable.
fn scene_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let page = app.router.scene().page();
    if matches!(page, crate::scene3d::VizPage::Summary) {
        return summary_keybindings(app);
    }
    if matches!(page, crate::scene3d::VizPage::Dfd) {
        let mut bindings = Vec::new();
        push_dfd_keybindings(&mut bindings, app);
        return bindings;
    }
    if matches!(page, crate::scene3d::VizPage::EntryPoints) {
        return entry_point_keybindings(app);
    }
    non_dfd_scene_keybindings(app, page)
}

// Summary is reachable before a threat model exists. With no model there are no
// components to select and the empty-state panel ignores scrolling, so advertise
// the one key that does something — the same generate affordance the empty DFD
// offers — instead of four dead navigation binds.
fn summary_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = if crate::ui_view_models::dfd_model_is_empty(app) {
        vec![bind("Enter", "generate DFD")]
    } else {
        vec![
            bind("j/k/↑/↓", "component"),
            bind("g/G", "ends"),
            bind("PgUp/PgDn", "scroll"),
            bind("Enter", "DFD target"),
        ]
    };
    push_scene_cycle_and_exit(&mut bindings, app);
    bindings
}

fn entry_point_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = vec![
        bind("j/k", "select"),
        bind("g/G", "ends"),
        bind("PgUp/PgDn", "detail"),
        bind("Enter", "DFD target"),
    ];
    if app.active_viz_pages().len() > 1 {
        bindings.push(bind("Tab", "next page"));
        bindings.push(bind("Shift+Tab", "prev page"));
    }
    bindings.push(bind("q", "leave"));
    bindings
}

fn non_dfd_scene_keybindings(
    app: &ShellApp,
    page: crate::scene3d::VizPage,
) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    if !page.is_frame_rendered() {
        bindings.push(bind("j/k/↑/↓", "scroll"));
        bindings.push(bind("g/G", "ends"));
    }
    if app.active_viz_pages().len() > 1 {
        bindings.push(bind("Tab", "next page"));
        bindings.push(bind("Shift+Tab", "prev page"));
    }
    bindings.push(bind("Esc/q", "leave"));
    if page.is_3d() {
        bindings.extend([
            bind("h/l/j/k", "orbit 3D"),
            bind("space/p", "pause"),
            bind("r", "reset"),
        ]);
    }
    bindings
}

fn push_scene_cycle_and_exit(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    if app.active_viz_pages().len() > 1 {
        bindings.push(bind("Tab", "next page"));
        bindings.push(bind("Shift+Tab", "prev page"));
    }
    bindings.push(bind("Esc/q", "leave"));
}

fn push_dfd_keybindings(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    if app.router.scene().dfd_focused() {
        bindings.push(bind("j/k/↑/↓", "context"));
        bindings.push(bind("g", "regenerate scope"));
        bindings.push(bind("Enter", "topology"));
        bindings.push(bind("Esc", "collapse"));
        bindings.push(bind("q", "leave"));
        return;
    }
    // Unlike Summary, both branches here read the model — `link_state` picks the
    // Enter label — and an empty model is an empty `DfdModel`, so the cheap
    // `dfd_model_is_empty` probe would buy nothing.
    let model = crate::ui_view_models::dfd_model(app);
    if model.empty_hint.is_some() {
        // `dfd_selectable_count` is 0 and there is no selection to detail, so
        // the cursor keys are inert. Advertise only the build that fills them.
        bindings.push(bind("Enter", "generate DFD"));
        push_scene_cycle_and_exit(bindings, app);
        return;
    }
    bindings.push(bind("j/k/↑/↓", "select"));
    bindings.push(bind("g", "regenerate scope"));
    if model.link_state == crate::ui_view_models::DfdLinkState::LegacyNeedsRebuild {
        bindings.push(bind("Enter", "rebuild linked context"));
    } else {
        bindings.push(bind("Enter", "context"));
    }
    bindings.push(bind("PgUp/PgDn", "detail"));
    push_scene_cycle_and_exit(bindings, app);
}

// SAST Tasks looks like a multi-select but is command-driven — advertise the
// verbs so the checkbox UI doesn't imply Space/Enter toggles that do nothing.
fn sast_tasks_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("task toggle <id>", "flip"));
    bindings.push(bind("task block <id>", "skip"));
    bindings.push(bind("task allow <id>", "enable"));
    bindings
}

// Each builder leads with the live view keybindings (scroll + Esc back) so the
// footer advertises the real keys, then adds command shortcuts for the view.
fn history_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("clear", "clear log"));
    bindings.push(bind("show runs", "ledger"));
    bindings.push(bind("story", "narrative"));
    bindings
}

fn story_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("show runs", "ledger"));
    bindings.push(bind("replay <id>", "replay run"));
    bindings
}

fn help_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("Ctrl+G", "palette"));
    bindings.push(bind("Ctrl+R", "reverse search"));
    bindings.push(bind("?<text>", "agent chat"));
    bindings.push(bind("Tab", "complete"));
    bindings.push(bind("Ctrl+P/N", "history prev/next"));
    bindings
}

fn tools_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("use <id>", "focus module"));
    bindings.push(bind("options <tool>", "configure"));
    bindings
}

fn health_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("auth", "credentials"));
    bindings.push(bind("config", "model/runtime"));
    bindings.push(bind("tools semgrep", "filter"));
    bindings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quit_confirm_keybindings_match_idle_and_active_exit_behavior() {
        assert_eq!(
            quit_confirm_keybindings(false),
            vec![bind("y/Y", "exit"), bind("n/N/Esc", "stay")]
        );
        assert_eq!(
            quit_confirm_keybindings(true),
            vec![
                bind("y/Y", "cancel if needed + exit"),
                bind("n/N/Esc", "stay"),
            ]
        );
    }
}
