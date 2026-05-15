use super::*;

pub(in crate::renderer::chrome::footer::keybindings) fn system_keybindings(
    app: &ShellApp,
) -> Option<Vec<(&'static str, &'static str)>> {
    let bindings = match app.shell_view {
        ShellView::History => vec![
            ("PgUp/PgDn", "scroll"),
            ("clear", "clear log"),
            ("show runs", "runs"),
            ("story", "story"),
        ],
        ShellView::Story => vec![
            ("history", "commands"),
            ("show runs", "runs"),
            ("replay <id>", "replay"),
            ("back", "home"),
        ],
        ShellView::Help => vec![
            // Mirrors `design/mockups/help.jsx` keybinds: highlight the
            // shell verbs that are always available so the help screen
            // doubles as a discovery surface.
            ("?<text>", "agent chat"),
            ("Tab", "complete"),
            ("Ctrl+R", "search history"),
            ("PgUp/PgDn", "scroll"),
            ("back", "modules"),
        ],
        ShellView::Tools => vec![
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("options <tool>", "options"),
            ("back", "home"),
        ],
        _ => return None,
    };
    Some(bindings)
}
