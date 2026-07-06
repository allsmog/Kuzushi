use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::History => Some(history_keybindings(app)),
        ShellView::Story => Some(story_keybindings(app)),
        ShellView::Help => Some(help_keybindings(app)),
        ShellView::Health => Some(health_keybindings(app)),
        ShellView::Tools => Some(tools_keybindings(app)),
        ShellView::Scene(page) => Some(scene_keybindings(page)),
        ShellView::SastTasks => Some(sast_tasks_keybindings(app)),
        // First-run pickers own input — surface their controls in the footer
        // so the modal has one canonical hint row.
        ShellView::PlanningPicker => Some(planning_picker_keybindings(app)),
        ShellView::FilePicker => Some(file_picker_keybindings()),
        ShellView::ModelPicker | ShellView::AuthMethodPicker(_) | ShellView::TargetPicker => {
            Some(choice_picker_keybindings(app))
        }
        _ => None,
    }
}

fn planning_picker_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    match app.planning_picker_route.focus() {
        crate::app::PickerFocus::Prompt => picker_prompt_keybindings(),
        crate::app::PickerFocus::OptionsPane => vec![
            bind("KEYS", "j/k option"),
            bind("Tab/Shift+Tab/o", "steps"),
            bind("1-4", "phase"),
            bind("Enter", "edit"),
            bind("Space", "cycle"),
            bind("S", "persist"),
            bind("Esc/q", "steps"),
            bind("COMMAND", ": type"),
        ],
        crate::app::PickerFocus::List => vec![
            bind("KEYS", "j/k move"),
            bind("h/l ←/→", "phase"),
            bind("1-4", "jump phase"),
            bind("Tab/Shift+Tab/o", "focus pane"),
            bind("Space", "check"),
            bind("a/n", "all/none"),
            bind("g", "rebuild cached"),
            bind("Enter", "run checked"),
            bind("s", "skip phase"),
            bind("Esc/q", "workbench"),
            bind("COMMAND", ": type"),
        ],
    }
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
    match app.shell_view {
        ShellView::ModelPicker => app.model_picker_route.focus() == crate::app::PickerFocus::Prompt,
        ShellView::AuthMethodPicker(_) => {
            app.auth_picker_route.focus() == crate::app::PickerFocus::Prompt
        }
        ShellView::TargetPicker => {
            app.target_picker_route.focus() == crate::app::PickerFocus::Prompt
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

// The security-viz gallery is fully interactive but its controls live only in
// the key handler; surface them so Tab/orbit/pause are discoverable.
fn scene_keybindings(page: crate::scene3d::VizPage) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    if !page.is_3d() {
        bindings.push(bind("j/k/g/G", "scroll"));
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
