use super::{bind, interrupt_binding, FooterKeybinding};
use crate::{InputMode, ShellApp, ShellView};

pub(super) fn owned_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.shell_view() != ShellView::Relationships {
        return None;
    }
    if let Some(review) = &app.router.relationships.bulk {
        return Some(bulk_bindings(app, review.stage));
    }
    if app.router.relationships.note.is_some() {
        return Some(vec![
            bind("Enter", "record"),
            bind("Esc", "cancel"),
            bind("Shift+Enter", "newline"),
            interrupt_binding(app),
        ]);
    }
    browser_bindings(app)
}

fn browser_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.router.relationships.show_groups {
        return group_bindings(app);
    }
    if app.input_mode() != InputMode::Navigate {
        return None;
    }
    Some(vec![
        bind("Space", "select"),
        bind("A", "review selected"),
        bind("a", "accept"),
        bind("r", "keep separate"),
        bind("u", "unlink"),
        bind("PgUp/PgDn", "details"),
        bind("Esc", "back"),
        bind("j/k", "select"),
        bind("n/p", "pages"),
        bind("R", "refresh"),
        bind("*", "select page"),
        bind("c", "clear selection"),
        interrupt_binding(app),
    ])
}

fn bulk_bindings(
    app: &ShellApp,
    stage: crate::app::RelationshipBulkStage,
) -> Vec<FooterKeybinding> {
    use crate::app::RelationshipBulkStage::*;
    let mut bindings = match stage {
        Review => vec![
            bind("Enter", "open source"),
            bind("[/]", "source side"),
            bind("a", "accept selection"),
            bind("r", "keep separate"),
            bind("u", "unlink selection"),
            bind("j/k", "inspect pairs"),
            bind("PgUp/PgDn", "details"),
            bind("Esc", "back"),
        ],
        Reason => vec![
            bind("Enter", "review confirmation"),
            bind("Esc", "back"),
            bind("Shift+Enter", "newline"),
        ],
        Confirm => vec![
            bind("Enter", "record all"),
            bind("Esc", "edit reason"),
            bind("PgUp/PgDn", "receipt"),
        ],
    };
    bindings.push(interrupt_binding(app));
    bindings
}

fn group_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    if app.input_mode() != InputMode::Navigate {
        return None;
    }
    Some(vec![
        bind("Enter", "open"),
        bind("Esc", "back"),
        bind("j/k", "select"),
        bind("n/p", "pages"),
        bind("R", "refresh"),
        bind("L/Tab", "relationships"),
        bind("PgUp/PgDn", "detail"),
        interrupt_binding(app),
    ])
}
