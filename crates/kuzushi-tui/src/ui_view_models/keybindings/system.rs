use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::History => Some(history_keybindings(app)),
        ShellView::Story => Some(story_keybindings(app)),
        ShellView::Help => Some(help_keybindings(app)),
        ShellView::Tools => Some(tools_keybindings(app)),
        ShellView::Scene(_) => Some(scene_keybindings()),
        ShellView::SastTasks => Some(sast_tasks_keybindings(app)),
        // First-run pickers print their controls to the log only — surface them
        // in the footer so the very first screen is operable without guessing.
        ShellView::PlanningPicker => Some(planning_picker_keybindings()),
        ShellView::ModelPicker | ShellView::AuthMethodPicker(_) | ShellView::TargetPicker => {
            Some(choice_picker_keybindings())
        }
        _ => None,
    }
}

fn planning_picker_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("j/k", "move"),
        bind("Space", "toggle"),
        bind("a/n", "all/none"),
        bind("g", "rebuild"),
        bind("Enter", "run"),
        bind("Esc", "skip"),
    ]
}

fn choice_picker_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("j/k", "move"),
        bind("Enter", "select"),
        bind("Esc", "skip"),
    ]
}

// The security-viz gallery is fully interactive but its controls live only in
// the key handler; surface them so Tab/orbit/pause are discoverable.
fn scene_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("Tab/S-Tab", "page"),
        bind("h/l/j/k", "orbit 3D"),
        bind("space/p", "pause"),
        bind("r", "reset"),
        bind("o", "return"),
        bind("Esc/q", "leave"),
    ]
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
