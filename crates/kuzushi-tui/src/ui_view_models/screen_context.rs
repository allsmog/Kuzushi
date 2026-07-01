use crate::app::{PaneFocus, ShellView, WorkbenchPane};
use crate::ShellApp;
use kuzushi_core::{stable_finding_alias, Finding};

mod model;

pub(crate) use model::{ScreenContext, ScreenCursor, ScreenRevision, ScreenSelectedItem};

const VISIBLE_ROW_LIMIT: usize = 8;
const VISIBLE_ROW_TEXT_LIMIT: usize = 160;

pub(crate) fn screen_context_model(app: &ShellApp) -> ScreenContext {
    ScreenContext {
        view: shell_view_label(&app.shell_view),
        focused_pane: focused_pane_label(app),
        selected_item: selected_item(app),
        selected_run: selected_run(app),
        selected_revision: selected_revision(app),
        active_phase: active_phase(app),
        active_filters: active_filters(app),
        selected_scope: selected_scope(app),
        visible_rows: visible_rows(app),
        cursor: ScreenCursor {
            row: active_cursor_row(app),
            col: app.cursor,
        },
    }
}

fn shell_view_label(view: &ShellView) -> String {
    let label = format!("{view:?}");
    let end = [label.find('('), label.find("{")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(label.len());
    label[..end].to_string()
}

fn focused_pane_label(app: &ShellApp) -> Option<String> {
    match app.shell_view {
        ShellView::Workbench => Some(workbench_pane_label(app.workbench_focus).to_string()),
        ShellView::Activity => app
            .activity
            .as_ref()
            .map(|activity| pane_focus_label(activity.effective_pane_focus()).to_string()),
        _ => None,
    }
}

fn workbench_pane_label(pane: WorkbenchPane) -> &'static str {
    match pane {
        WorkbenchPane::Source => "Source",
        WorkbenchPane::Center => "Center",
        WorkbenchPane::Findings => "Findings",
        WorkbenchPane::Details => "Details",
    }
}

fn pane_focus_label(pane: PaneFocus) -> &'static str {
    match pane {
        PaneFocus::Left => "Dag",
        PaneFocus::Right => "Output",
    }
}

fn selected_item(app: &ShellApp) -> Option<ScreenSelectedItem> {
    let finding = app
        .selected_finding
        .as_ref()
        .or_else(|| app.findings.get(app.findings_cursor))?;
    Some(selected_item_from_finding(app, finding))
}

fn selected_item_from_finding(app: &ShellApp, finding: &Finding) -> ScreenSelectedItem {
    ScreenSelectedItem {
        alias: stable_finding_alias(&app.findings, &finding.fingerprint),
        fingerprint: finding.fingerprint.clone(),
        title: finding.title.clone(),
        file: finding.file_path.clone(),
        line: finding.start_line,
        rank: finding.severity.as_str().to_string(),
        state: classification_state(finding),
        confirmation: confirmation_state(finding),
    }
}

fn classification_state(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str().to_string())
        .unwrap_or_else(|| "untriaged".to_string())
}

fn confirmation_state(finding: &Finding) -> String {
    finding
        .verification
        .as_ref()
        .map(|verification| verification.proof_verdict.as_str().to_string())
        .unwrap_or_else(|| "unconfirmed".to_string())
}

fn selected_run(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Replay(run_id) | ShellView::Trace(run_id) => Some(run_id.clone()),
        ShellView::RunDiff { left, right } => Some(format!("{left} -> {right}")),
        _ => app
            .tool_run_id
            .clone()
            .or_else(|| app.scan.as_ref().and_then(|scan| scan.run_id.clone()))
            .or_else(|| {
                app.activity
                    .as_ref()
                    .map(|activity| activity.run_id.clone())
            })
            .or_else(|| {
                app.agent_chat
                    .as_ref()
                    .and_then(|agent| agent.run_id.clone())
            }),
    }
}

fn selected_revision(app: &ShellApp) -> Option<ScreenRevision> {
    app.workbench_cache
        .borrow_mut()
        .git_metadata(app.target.as_deref())
        .map(ScreenRevision::from)
}

fn active_phase(app: &ShellApp) -> Option<String> {
    super::journey_model(app).map(|journey| journey.current.word().to_string())
}

fn active_filters(app: &ShellApp) -> Vec<String> {
    match &app.shell_view {
        ShellView::Options(view) => vec![format!("options:{}", view.filter.label())],
        _ => Vec::new(),
    }
}

fn selected_scope(app: &ShellApp) -> Option<String> {
    super::active_project_scope_label(app).or_else(|| {
        app.target
            .as_ref()
            .map(|path| super::compact_target_path(&path.to_string_lossy()))
    })
}

fn visible_rows(app: &ShellApp) -> Vec<String> {
    match app.shell_view {
        ShellView::Runs => visible_run_rows(app),
        ShellView::RunDiff {
            ref left,
            ref right,
        } => visible_run_diff_rows(app, left, right),
        ShellView::Activity => visible_activity_rows(app),
        ShellView::StrategyQueue => visible_strategy_rows(app),
        _ => visible_finding_rows(app),
    }
}

fn visible_finding_rows(app: &ShellApp) -> Vec<String> {
    super::findings_model(app)
        .rows
        .iter()
        .take(VISIBLE_ROW_LIMIT)
        .map(|row| {
            bounded_row(format!(
                "{} {} {} {} {} {} {}",
                row.alias,
                row.severity_label,
                row.verdict,
                row.run_label,
                row.revision_label,
                row.title,
                row.location
            ))
        })
        .collect()
}

fn visible_run_rows(app: &ShellApp) -> Vec<String> {
    super::run_timeline_model(app, VISIBLE_ROW_LIMIT)
        .rows
        .iter()
        .take(VISIBLE_ROW_LIMIT)
        .map(|row| bounded_row(row.cells.join(" ")))
        .collect()
}

fn visible_run_diff_rows(app: &ShellApp, left: &str, right: &str) -> Vec<String> {
    let model = super::run_diff_model(app, left, right);
    model
        .added
        .iter()
        .map(|row| format!("added {} {} {}", row.severity, row.title, row.location))
        .chain(
            model
                .removed
                .iter()
                .map(|row| format!("removed {} {} {}", row.severity, row.title, row.location)),
        )
        .take(VISIBLE_ROW_LIMIT)
        .map(bounded_row)
        .collect()
}

fn visible_activity_rows(app: &ShellApp) -> Vec<String> {
    app.activity
        .as_ref()
        .map(|activity| {
            activity
                .events
                .iter()
                .rev()
                .take(VISIBLE_ROW_LIMIT)
                .map(|event| {
                    bounded_row(format!(
                        "{} {} {}",
                        event.step.kind,
                        event.step.verb.as_deref().unwrap_or("-"),
                        event.step.label
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn visible_strategy_rows(app: &ShellApp) -> Vec<String> {
    super::strategy_queue_model(app)
        .rows
        .iter()
        .take(VISIBLE_ROW_LIMIT)
        .map(|row| {
            bounded_row(format!(
                "{} {} {}",
                row.cells.join(" "),
                row.lineage,
                row.rationale
            ))
        })
        .collect()
}

fn bounded_row(value: String) -> String {
    if value.chars().count() <= VISIBLE_ROW_TEXT_LIMIT {
        return value;
    }
    format!(
        "{}...",
        value
            .chars()
            .take(VISIBLE_ROW_TEXT_LIMIT)
            .collect::<String>()
    )
}

fn active_cursor_row(app: &ShellApp) -> usize {
    match app.shell_view {
        ShellView::Workbench => match app.workbench_focus {
            WorkbenchPane::Findings => app.findings_cursor,
            pane => app.workbench_scroll.get(pane) as usize,
        },
        ShellView::Runs => app.scroll_offset as usize,
        ShellView::Activity => app
            .activity
            .as_ref()
            .map(|activity| match activity.effective_pane_focus() {
                PaneFocus::Left => activity.task_scroll,
                PaneFocus::Right => activity.feed_scroll,
            })
            .unwrap_or_default(),
        _ => app.scroll_offset as usize,
    }
}

trait OptionsFilterLabel {
    fn label(self) -> &'static str;
}

impl OptionsFilterLabel for crate::app::OptionsFilter {
    fn label(self) -> &'static str {
        match self {
            crate::app::OptionsFilter::Standard => "standard",
            crate::app::OptionsFilter::Advanced => "advanced",
            crate::app::OptionsFilter::Missing => "missing",
        }
    }
}

#[cfg(test)]
mod tests;
