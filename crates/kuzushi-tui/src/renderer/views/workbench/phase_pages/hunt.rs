use super::*;
use crate::renderer::views::scene::diagrams::heatmap_lines;
use crate::ui_view_models::HuntPhaseModel;
use ratatui::layout::{Constraint, Direction, Layout};

const REFERENCE_LAYOUT_MIN_WIDTH: u16 = 120;
const GRID_LAYOUT_MIN_WIDTH: u16 = 80;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    if let Some(pane) = state.zoom {
        render_zoomed(frame, area, app, model, state, pane);
        return;
    }
    if area.width >= REFERENCE_LAYOUT_MIN_WIDTH {
        render_reference(frame, area, app, model, state);
    } else if area.width >= GRID_LAYOUT_MIN_WIDTH {
        render_grid(frame, area, app, model, state);
    } else {
        render_compact(frame, area, app, model, state);
    }
}

pub(super) fn plain_lines(model: &HuntPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = divider_lines(
        "SOURCE",
        super::super::panes::source_pane_lines(&model.source, width),
        width,
    );
    lines.extend(divider_lines("HUNT", strategy_lines(model, width), width));
    lines.extend(divider_lines(
        "REVIEW QUEUE",
        super::super::panes::review_queue_pane_lines(
            &model.review,
            Rect::new(0, 0, width.min(u16::MAX as usize) as u16, u16::MAX),
        ),
        width,
    ));
    lines.extend(divider_lines(
        "FINDINGS HEATMAP",
        heatmap_lines(width, &model.heatmap),
        width,
    ));
    lines
}

fn render_reference(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(36),
            Constraint::Percentage(42),
        ])
        .split(rows[0]);
    render_source(frame, top[0], model, state);
    render_hunt(frame, top[1], app, model, state);
    render_review(frame, top[2], model, state);
    render_heatmap(frame, rows[1], model, state);
}

fn render_grid(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);
    let top = split_grid_row(rows[0]);
    let bottom = split_grid_row(rows[1]);
    render_source(frame, top[0], model, state);
    render_hunt(frame, top[1], app, model, state);
    render_review(frame, bottom[0], model, state);
    render_heatmap(frame, bottom[1], model, state);
}

fn render_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(24),
            Constraint::Percentage(34),
            Constraint::Percentage(20),
        ])
        .split(area);
    render_source(frame, rows[0], model, state);
    render_hunt(frame, rows[1], app, model, state);
    render_review(frame, rows[2], model, state);
    render_heatmap(frame, rows[3], model, state);
}

fn split_grid_row(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area)
}

fn render_zoomed(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
    pane: WorkbenchPane,
) {
    match pane {
        WorkbenchPane::Source => render_source(frame, area, model, state),
        WorkbenchPane::Center => render_hunt(frame, area, app, model, state),
        WorkbenchPane::Findings => render_review(frame, area, model, state),
        WorkbenchPane::Details => render_heatmap(frame, area, model, state),
    }
}

fn render_source(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        format!("SOURCE · {}", model.source.file_count),
        super::super::panes::source_pane_lines(
            &model.source,
            area.width.saturating_sub(2) as usize,
        ),
        WorkbenchPane::Source,
        state,
    );
}

fn render_hunt(
    frame: &mut Frame<'_>,
    area: Rect,
    _app: &ShellApp,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "HUNT",
        strategy_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Center,
        state,
    );
}

fn render_review(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        format!("REVIEW QUEUE · {}", model.review.visible_count),
        super::super::panes::review_queue_pane_lines(
            &model.review,
            Rect::new(
                0,
                0,
                area.width.saturating_sub(2),
                area.height.saturating_sub(1),
            ),
        ),
        WorkbenchPane::Findings,
        state,
    );
}

fn render_heatmap(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &HuntPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "FINDINGS HEATMAP",
        heatmap_lines(area.width.saturating_sub(2) as usize, &model.heatmap),
        WorkbenchPane::Details,
        state,
    );
}

fn strategy_lines(model: &HuntPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(&model.strategy.summary, width),
        theme::muted(),
    )];
    if model.strategy.rows.is_empty() {
        lines.extend(empty_state_panel(
            "no hunt proposals",
            &["run `recommend` to rank detectors and hunts"],
            &[
                ("recommend", "generate proposals"),
                ("scan", "start the hunt"),
            ],
        ));
        return lines;
    }
    lines.extend(model.strategy.rows.iter().take(8).map(|row| {
        Line::styled(
            fit(
                &format!("{}  {}  {}", row.cells[0], row.id, row.cells[3]),
                width,
            ),
            strategy_style(&row.cells[0]),
        )
    }));
    lines
}

fn strategy_style(status: &str) -> ratatui::style::Style {
    match status {
        "approved" | "done" => theme::success(),
        "running" => theme::accent(),
        "failed" | "blocked" => theme::danger(),
        "rejected" => theme::muted(),
        _ => theme::primary(),
    }
}
