use super::{bind, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::History => Some(history_keybindings()),
        ShellView::Story => Some(story_keybindings()),
        ShellView::Help => Some(help_keybindings()),
        ShellView::Tools => Some(tools_keybindings()),
        _ => None,
    }
}

fn history_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("PgUp/PgDn", "scroll"),
        bind("clear", "clear log"),
        bind("show runs", "ledger"),
        bind("story", "narrative"),
    ]
}

fn story_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("history", "commands"),
        bind("show runs", "ledger"),
        bind("replay <id>", "replay run"),
        bind("back", "home"),
    ]
}

fn help_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("?<text>", "agent chat"),
        bind("Tab", "complete"),
        bind("Ctrl+P/N", "history prev/next"),
        bind("PgUp/PgDn", "scroll"),
        bind("back", "modules"),
    ]
}

fn tools_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("PgUp/PgDn", "scroll"),
        bind("use <id>", "focus module"),
        bind("options <tool>", "configure"),
        bind("back", "home"),
    ]
}
