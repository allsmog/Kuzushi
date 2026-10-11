use super::{bind, interrupt_binding, FooterKeybinding};
use crate::{InputMode, ShellApp, ShellView};

pub(super) fn owned_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.shell_view() != ShellView::Lessons {
        return None;
    }
    if let Some(bindings) = dialog_bindings(app) {
        return Some(bindings);
    }
    if app.input_mode() != InputMode::Navigate {
        return None;
    }
    Some(vec![
        bind("j/k", "select"),
        bind("n", "new draft"),
        bind("g", "model draft"),
        bind("e", "edit"),
        bind("d", "resume draft"),
        bind("a/r/t", "review"),
        bind("Space", "select lesson"),
        bind("u", "context copy"),
        bind("c", "clear selection"),
        bind("[/]", "pages"),
        bind("R", "refresh"),
        bind("Esc", "back"),
        interrupt_binding(app),
    ])
}

fn dialog_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.router.lessons.context_selecting {
        return Some(context_bindings(app));
    }
    if !app.router.lessons.form_visible {
        return None;
    }
    let form = app.router.lessons.form.as_ref()?;
    if form.confirming {
        return Some(vec![
            bind("Enter", "record reviewed action"),
            bind("Esc", "edit"),
            bind("PgUp/PgDn", "inspect"),
            interrupt_binding(app),
        ]);
    }
    Some(vec![
        bind("Enter", "inspect confirmation"),
        bind("Esc", "retain draft"),
        bind("Tab/Shift+Tab", "fields"),
        bind("Shift+Enter", "newline"),
        interrupt_binding(app),
    ])
}

fn context_bindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if app.router.lessons.context_confirm.is_some() {
        return vec![
            bind("Enter", "create copy"),
            bind("Esc", "choose base"),
            bind("PgUp/PgDn", "inspect"),
            interrupt_binding(app),
        ];
    }
    vec![
        bind("Enter", "review copy"),
        bind("j/k", "choose base"),
        bind("Esc", "back"),
        interrupt_binding(app),
    ]
}
