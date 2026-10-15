use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    match app.shell_view() {
        ShellView::Options => Some(options_keybindings(app)),
        ShellView::Context => Some(context_keybindings(app)),
        ShellView::StrategyQueue => Some(strategy_queue_keybindings(app)),
        ShellView::Workspace => Some(workspace_status_keybindings(app)),
        ShellView::KnowledgeBase => Some(knowledge_base_keybindings(app)),
        _ => None,
    }
}

// Each builder leads with the live view keybindings (scroll + Esc back) so the
// footer advertises the real keys, then adds command shortcuts for the view.
fn options_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.router.options_browser().edit.is_some() || app.input_mode() == crate::InputMode::Navigate
    {
        return options_browser_keybindings(app);
    }
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("set key value", "session opt"));
    bindings.push(bind("show advanced", "advanced opts"));
    bindings.push(bind("show missing", "required"));
    bindings
}

pub(in crate::ui_view_models) fn options_browser_keybindings(
    app: &ShellApp,
) -> Vec<FooterKeybinding> {
    if let Some(edit) = app.router.options_browser().edit.as_ref() {
        let save = if edit.global {
            "save globally"
        } else {
            "save session"
        };
        return vec![
            bind("Enter/Ctrl+S", save),
            bind("Ctrl+G", "global"),
            bind("Esc", "keep draft"),
            bind("PgUp/Dn", "error"),
            bind("Shift+Enter", "newline"),
        ];
    }
    vec![
        bind("Esc", option_browser_back_label(app)),
        bind("↑/↓ j/k", "option"),
        bind("Enter", option_browser_enter_label(app)),
        bind("PgUp/Dn", "details"),
        bind("s/a/m", "standard/advanced/missing"),
    ]
}

fn option_browser_back_label(app: &ShellApp) -> &'static str {
    if app.router.options_browser().support_origin.is_some() {
        return "tools";
    }
    "prompt"
}

fn option_browser_enter_label(app: &ShellApp) -> &'static str {
    let selected = app.selected_browser_option();
    let workflow = app
        .option_browser_rows()
        .iter()
        .any(|row| Some(&row.cells[0]) == selected.as_ref() && row.cells[4] == "workflow");
    if workflow {
        "workflow details"
    } else {
        "edit"
    }
}

fn context_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("context build", "rebuild"));
    bindings.push(bind("context status", "summary"));
    bindings.push(bind("context regen repo", "refresh index"));
    bindings
}

fn workspace_status_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("workspace status", "summary"));
    bindings.push(bind("workspace scope init", "scope file"));
    bindings.push(bind("workspace export", "export findings"));
    bindings.push(bind("target <path>", "select target"));
    bindings.push(bind("full <path>", "guided Map → Scan"));
    bindings
}

fn strategy_queue_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("strategy keep <id>", "approve"));
    bindings.push(bind("strategy skip <id>", "reject"));
    bindings.push(bind("strategy fire", "run approved"));
    bindings.push(bind("strategy correct <id>", "correct"));
    bindings.push(bind("strategy inspect <id>", "recorded details"));
    bindings.push(bind("recommendations", "inspect or refresh suggestions"));
    bindings
}

fn knowledge_base_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let mut bindings = Vec::new();
    push_view_keybindings(&mut bindings, app);
    bindings.push(bind("attach <path>", "add file"));
    bindings.push(bind("detach <id>", "remove"));
    bindings.push(bind("reparse <id>", "refresh"));
    bindings
}
