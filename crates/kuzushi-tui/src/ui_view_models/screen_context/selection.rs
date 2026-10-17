//! Bind screen selections to the page being viewed, separately from workflow progress.
use crate::app::{ShellView, WorkbenchPage};
use crate::ShellApp;
use kuzushi_core::WorkflowPhase;

pub(super) fn finding_context_is_visible(app: &ShellApp) -> bool {
    app.shell_view() == ShellView::Workbench
        && matches!(
            crate::ui_view_models::active_workbench_page(app),
            WorkbenchPage::Review | WorkbenchPage::Prove | WorkbenchPage::Fix
        )
}

pub(super) fn displayed_phase(app: &ShellApp) -> Option<String> {
    if !crate::ui_view_models::journey::investigation_chrome_is_visible(app) {
        return None;
    }
    match app.shell_view() {
        ShellView::Workbench => Some(
            crate::ui_view_models::active_workbench_page(app)
                .title()
                .to_ascii_lowercase(),
        ),
        ShellView::Report => Some("report".into()),
        ShellView::Activity => app
            .activity()
            .and_then(|activity| activity.origin_phase)
            .map(|phase| {
                WorkbenchPage::from_phase(phase)
                    .title()
                    .to_ascii_lowercase()
            }),
        _ => None,
    }
}

pub(super) fn selected_runs(app: &ShellApp) -> Vec<String> {
    match app.shell_view() {
        ShellView::Workbench => workbench_runs(app),
        ShellView::Report => report_runs(app),
        _ => utility_runs(app),
    }
}

fn workbench_runs(app: &ShellApp) -> Vec<String> {
    let page = crate::ui_view_models::active_workbench_page(app);
    let attempt = if page == WorkbenchPage::Review {
        app.engagement
            .selected_phase_attempt(WorkflowPhase::Scan)
            .or_else(|| {
                app.engagement
                    .stale_selected_phase_attempt(WorkflowPhase::Scan)
            })
    } else {
        app.engagement
            .displayed_phase_attempt(page.phase())
            .map(|(attempt, _)| attempt)
    };
    attempt
        .map(|attempt| attempt.completed.run_refs.clone())
        .unwrap_or_default()
}

fn report_runs(app: &ShellApp) -> Vec<String> {
    if app.router.report().workspace_history() {
        return Vec::new();
    }
    app.workbench_cache()
        .borrow()
        .cached_report_run_refs(app.target(), &app.report_hydration_key())
        .unwrap_or_default()
}

fn utility_runs(app: &ShellApp) -> Vec<String> {
    match app.shell_view() {
        ShellView::Replay => vec![app.router.replay().run_id_owned()],
        ShellView::Trace => vec![app.router.trace().run_id_owned()],
        ShellView::Activity => app
            .activity()
            .map(|activity| vec![activity.run_id.clone()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub(super) fn single_run_label(app: &ShellApp, runs: &[String]) -> Option<String> {
    if app.shell_view() == ShellView::RunDiff {
        return Some(app.router.run_diff().label());
    }
    match runs {
        [run] => Some(run.clone()),
        _ => None,
    }
}
