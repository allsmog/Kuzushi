use super::{bind, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view {
        ShellView::Options(_) => Some(options_keybindings()),
        ShellView::Context => Some(context_keybindings()),
        ShellView::Workspace => Some(workspace_status_keybindings()),
        ShellView::KnowledgeBase => Some(knowledge_base_keybindings()),
        _ => None,
    }
}

fn options_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("set key value", "session opt"),
        bind("show advanced", "advanced opts"),
        bind("show missing", "required"),
        bind("back", "module"),
    ]
}

fn context_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("context build", "rebuild"),
        bind("context status", "summary"),
        bind("context regen repo", "refresh index"),
        bind("back", "module"),
    ]
}

fn workspace_status_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("workspace status", "summary"),
        bind("workspace export", "export findings"),
        bind("scan <target>", "select target"),
        bind("back", "module"),
    ]
}

fn knowledge_base_keybindings() -> Vec<FooterKeybinding> {
    vec![
        bind("PgUp/PgDn", "scroll"),
        bind("attach <path>", "add file"),
        bind("detach <id>", "remove"),
        bind("reparse <id>", "refresh"),
    ]
}
