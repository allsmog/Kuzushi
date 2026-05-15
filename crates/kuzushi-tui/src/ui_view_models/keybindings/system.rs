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
        bind("show runs", "runs"),
        bind("story", "story"),
    ]
}

fn story_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("history", "commands"),
        bind("show runs", "runs"),
        bind("replay <id>", "replay"),
        bind("back", "home"),
    ]
}

fn help_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("?<text>", "agent chat"),
        bind("Tab", "complete"),
        bind("Ctrl+R", "search history"),
        bind("PgUp/PgDn", "scroll"),
        bind("back", "modules"),
    ]
}

fn tools_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("PgUp/PgDn", "scroll"),
        bind("use <id>", "focus module"),
        bind("options <tool>", "options"),
        bind("back", "home"),
    ]
}
