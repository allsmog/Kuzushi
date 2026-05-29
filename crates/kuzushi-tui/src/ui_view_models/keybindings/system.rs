use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::History => Some(history_keybindings(app)),
        ShellView::Story => Some(story_keybindings(app)),
        ShellView::Help => Some(help_keybindings(app)),
        ShellView::Tools => Some(tools_keybindings(app)),
        _ => None,
    }
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
