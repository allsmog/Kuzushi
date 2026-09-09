use super::{bind, workbench_plan, FooterKeybinding, ShellApp};
use crate::app::state_transitions::ViewHotkeyAction;
use crate::app::{InputMode, InvestigationBoundary};

/// The visible reader/form owns its controls while a phase result waits behind it.
pub(in crate::ui_view_models::keybindings) fn prove_detail_bindings(
    app: &ShellApp,
) -> Option<Vec<FooterKeybinding>> {
    if !app.prove_detail_owns_controls() {
        return None;
    }
    if app.input_mode() == InputMode::Prompt {
        return empty_detail_prompt_bindings(app);
    }
    let plan = workbench_plan(app);
    let mut bindings: Vec<_> = app
        .workbench_view_keybindings_for_plan(plan.as_ref())
        .into_iter()
        .filter_map(|binding| {
            detail_action_label(app, binding.action).map(|label| bind(binding.hint, label))
        })
        .collect();
    // The paired Page Up/Down actions share one adjacent footer hint.
    bindings.dedup();
    bindings.insert(0, bind("Esc", super::super::reader_escape_label(app)));
    Some(bindings)
}

fn empty_detail_prompt_bindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    (app.input().is_empty() && app.editor().completion_cycle().is_none())
        .then(|| vec![bind("Esc", super::super::reader_escape_label(app))])
}

fn detail_action_label(app: &ShellApp, action: ViewHotkeyAction) -> Option<&'static str> {
    match action {
        ViewHotkeyAction::WorkbenchOpen => detail_can_draft(app).then_some("draft"),
        ViewHotkeyAction::ViewPageDown | ViewHotkeyAction::ViewPageUp => Some("scroll"),
        ViewHotkeyAction::WorkbenchInvestigationBoundary => {
            app.router.workbench().investigation_draft().map(|_| "mode")
        }
        _ => None,
    }
}

fn detail_can_draft(app: &ShellApp) -> bool {
    let Some(boundary) = app.router.workbench().investigation_draft() else {
        return app.router.workbench().trace_view_open();
    };
    boundary == InvestigationBoundary::StaticOnly
        || app
            .router
            .workbench()
            .investigation_readiness()
            .is_some_and(|readiness| readiness.can_attempt())
}
