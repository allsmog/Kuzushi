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
        ShellView::Scene => Some(scene_keybindings(app.router.scene().page())),
        ShellView::SastTasks => Some(sast_tasks_keybindings(app)),
        // First-run pickers own input — surface their controls in the footer
        // so the modal has one canonical hint row.
        ShellView::PlanningPicker => Some(planning_picker_keybindings(app)),
        ShellView::Setup => Some(setup_keybindings(app)),
        ShellView::Report => Some(report_keybindings(app)),
        ShellView::FilePicker => Some(file_picker_keybindings()),
        ShellView::TargetPicker => Some(choice_picker_keybindings(app)),
        _ => None,
    }
}

fn report_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.router.report().editing_path() {
        return vec![
            bind("type", "destination"),
            bind("Backspace", "delete"),
            bind("Enter", "save"),
            bind("Esc", "cancel"),
        ];
    }
    vec![
        bind("j/k", "format"),
        bind("c", "completeness"),
        bind("e", "edit path"),
        bind("Enter", "export/retry"),
        bind("o", "reveal"),
        bind("Esc/q", "return"),
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
    if app.router.setup().editor() == Some(crate::app::SetupEditor::Budget) {
        return vec![
            bind("type", "budget USD"),
            bind("Backspace", "delete"),
            bind("Delete", "unset"),
            bind("Enter", "save"),
            bind("Esc", "cancel"),
        ];
    }
    vec![
        bind("j/k", "move"),
        bind("Enter", "open/start"),
        bind("Esc/q", "workbench"),
        bind("Ctrl+C", "exit"),
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
            bind("type", "edit value"),
            bind("Backspace", "delete"),
            bind("Enter", "save"),
            bind("Esc", "cancel"),
        ];
    }
    match app.engagement.planning_picker().focus() {
        crate::app::PickerFocus::Prompt => picker_prompt_keybindings(),
        crate::app::PickerFocus::OptionsPane
            if app.engagement.planning_picker().returns_to_setup() =>
        {
            vec![
                bind("KEYS", "j/k option"),
                bind("Tab/Shift+Tab/o", "tasks"),
                bind("Enter", "edit"),
                bind("Space", "cycle"),
                bind("Esc/q", "tasks"),
            ]
        }
        crate::app::PickerFocus::OptionsPane => vec![
            bind("KEYS", "j/k option"),
            bind("Tab/Shift+Tab/o", "steps"),
            bind("1-5", "phase"),
            bind("Enter", "edit"),
            bind("Space", "cycle"),
            bind("S", "persist"),
            bind("Esc/q", "steps"),
            bind("COMMAND", ": type"),
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
        bind("KEYS", "j/k move"),
        bind("h/l ←/→", "phase"),
        bind("1-5", "jump phase"),
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
            bindings.push(bind("Tab/Shift+Tab/o", "focus pane"));
            bindings.push(bind("Space", "check"));
            bindings.push(bind("Enter", "run checked"));
        }
    }
    bindings.extend([
        bind("a/n", "all/none"),
        bind("g", "rebuild cached"),
        bind("s", "skip phase"),
        bind("Esc/q", "workbench"),
        bind("COMMAND", ": type"),
    ]);
    bindings
}

fn setup_plan_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("KEYS", "j/k move"),
        bind("Space", "check"),
        bind("Tab/Shift+Tab/o", "focus pane"),
        bind("p", "review prompt"),
        bind("Enter", "save to Setup"),
        bind("Esc/q", "return to Setup"),
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
    vec![
        bind("j/k", "move"),
        bind("demo", "offline"),
        bind(":", "type command"),
        bind("Enter", "select"),
        bind("Esc", "skip"),
    ]
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

fn file_picker_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("type", "filter"),
        bind("j/k", "move"),
        bind("Enter", "attach"),
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
fn scene_keybindings(page: crate::scene3d::VizPage) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    if matches!(page, crate::scene3d::VizPage::Dfd) {
        // Selection moves through topology; paging scrolls only the wrapped
        // detail panel, never the graph itself.
        bindings.push(bind("j/k/↑/↓", "select node/flow"));
        bindings.push(bind("PgUp/PgDn", "scroll details"));
    } else if !page.is_3d() {
        bindings.push(bind("j/k/↑/↓", "scroll"));
        bindings.push(bind("g/G", "ends"));
    }
    bindings.extend([
        bind("Tab", "next page"),
        bind("Shift+Tab", "prev page"),
        bind("Esc/q", "leave"),
    ]);
    if page.is_3d() {
        bindings.extend([
            bind("h/l/j/k", "orbit 3D"),
            bind("space/p", "pause"),
            bind("r", "reset"),
        ]);
    }
    bindings
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
