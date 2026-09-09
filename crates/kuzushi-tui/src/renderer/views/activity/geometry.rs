use super::*;
use crate::ui_view_models::{ActivityPaneLayout, ActivityViewModel, RunFocusModel};
use std::time::Instant;

pub(super) struct ActivityGeometry {
    pub header: Rect,
    pub footer: Rect,
    pub tasks: Option<Rect>,
    pub output: Option<Rect>,
}

pub(crate) struct ActivityOutputScroll {
    pub max_offset: usize,
    pub page_rows: usize,
}

pub(crate) fn activity_output_scroll(app: &ShellApp) -> Option<ActivityOutputScroll> {
    if app.shell_view() != ShellView::Activity {
        return None;
    }
    let ActivityViewModel::Active(model) = crate::ui_view_models::activity_view_model(app) else {
        return None;
    };
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let area = crate::renderer::workbench_primary_area(app, full);
    let output = activity_geometry(&model, area, Instant::now()).output?;
    let inner = cockpit_pane_block("OUTPUT", true).inner(output);
    let rows = model.feed_pane_rows(usize::from(inner.width));
    Some(ActivityOutputScroll {
        max_offset: rows.len().saturating_sub(usize::from(inner.height)),
        // Overflow disclosures can occupy a row at each end of the pane.
        page_rows: usize::from(inner.height.saturating_sub(2)).max(1),
    })
}

pub(super) fn activity_geometry(
    model: &RunFocusModel<'_>,
    area: Rect,
    now: Instant,
) -> ActivityGeometry {
    let health_rows = model.heartbeat_rows(area.width, now).1.len();
    let mut frame = model.frame_layout(area.width, health_rows);
    if let Some(chrome) = model.compact_chrome(area.width, area.height) {
        frame.header_rows = u16::try_from(chrome.header.len()).unwrap_or(u16::MAX);
        frame.footer_rows = u16::try_from(chrome.footer.len()).unwrap_or(u16::MAX);
    }
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(frame.header_rows),
            Constraint::Min(0),
            Constraint::Length(frame.footer_rows),
        ])
        .split(area);
    let (tasks, output) = activity_panes(model, outer[1], now);
    ActivityGeometry {
        header: outer[0],
        footer: outer[2],
        tasks,
        output,
    }
}

fn activity_panes(
    model: &RunFocusModel<'_>,
    area: Rect,
    now: Instant,
) -> (Option<Rect>, Option<Rect>) {
    if model.collapse_dag_pane() {
        return (None, Some(area));
    }
    tasked_panes(model.pane_layout(area.width, area.height, now), area, model)
}

fn tasked_panes(
    layout: ActivityPaneLayout,
    area: Rect,
    model: &RunFocusModel<'_>,
) -> (Option<Rect>, Option<Rect>) {
    match layout {
        ActivityPaneLayout::Focused => focused_pane(area, model.pane_chrome().dag.focused),
        ActivityPaneLayout::Stacked { task_height } => {
            split_panes(area, Direction::Vertical, task_height, 3)
        }
        ActivityPaneLayout::SideBySide { task_width } => {
            split_panes(area, Direction::Horizontal, task_width, 48)
        }
    }
}

fn focused_pane(area: Rect, tasks_focused: bool) -> (Option<Rect>, Option<Rect>) {
    if tasks_focused {
        (Some(area), None)
    } else {
        (None, Some(area))
    }
}

fn split_panes(
    area: Rect,
    direction: Direction,
    task_size: u16,
    output_minimum: u16,
) -> (Option<Rect>, Option<Rect>) {
    let panes = Layout::default()
        .direction(direction)
        .constraints([
            Constraint::Length(task_size),
            Constraint::Min(output_minimum),
        ])
        .split(area);
    (Some(panes[0]), Some(panes[1]))
}
