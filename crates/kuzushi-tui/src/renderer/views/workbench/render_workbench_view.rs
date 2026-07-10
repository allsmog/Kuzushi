use super::detail_pane::detail_pane_lines;
use super::panes::{
    center_pane_lines, hunt_control_lines, review_queue_pane_lines, ship_chain_lines,
    ship_export_lines, ship_patch_lines, source_pane_lines, source_title,
    terrain_attack_surface_lines, terrain_material_lines, terrain_visual_lines,
};
use super::*;
use crate::app::{WorkbenchPage, WorkbenchPane};
use crate::renderer::views::scene::{DfdDiagram, TreeDiagram};
use crate::ui_view_models::{
    attack_tree, dfd_model, workbench_view_model, JourneyPhaseStatus, ReviewQueueModel,
    WorkbenchCenter, WorkbenchCenterTab, WorkbenchHint, WorkbenchTopBar, WorkbenchViewModel,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::Modifier;
use ratatui::widgets::{Block, Paragraph, Wrap};

const FOUR_COLUMN_MIN_WIDTH: u16 = 150;
const REVIEW_GRID_MIN_WIDTH: u16 = 100;
const STACKED_MIN_BODY_HEIGHT: u16 = 21;

/// Frame-level renderer for the Workbench command center. Owns the whole body
/// region: a `Kuzushi · project · target · LIVE · phase` top bar over a
/// responsive review cockpit. Wide terminals show four columns; middle widths
/// keep CENTER/FINDINGS/DETAILS; narrow tall terminals stack all panes; narrow
/// short terminals collapse to the review path. The prompt + keybind footer are
/// drawn by the shell chrome below `area`.
pub(crate) fn render_workbench_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let model = workbench_view_model(app);
    let mut top_lines = top_bar_lines(
        &model.top_bar,
        &model.command_bar_hints,
        area.width as usize,
    );
    if let Some(pane) = model.zoom {
        top_lines.push(zoom_status_line(pane));
    }
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_lines.len() as u16),
            Constraint::Min(0),
        ])
        .split(area);
    frame.render_widget(Paragraph::new(top_lines), outer[0]);
    render_body(frame, outer[1], app, &model);
}

fn zoom_status_line(pane: WorkbenchPane) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ▸ ZOOM ", theme::warn()),
        Span::styled(workbench_pane_label(pane), theme::primary()),
        Span::styled(" · Tab pane · Z restore cockpit", theme::muted()),
    ])
}

fn workbench_pane_label(pane: WorkbenchPane) -> &'static str {
    match pane {
        WorkbenchPane::Source => "SOURCE",
        WorkbenchPane::Center => "CENTER",
        WorkbenchPane::Findings => "FINDINGS",
        WorkbenchPane::Details => "DETAILS",
    }
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    if area.width < 8 || area.height < 3 {
        return;
    }
    if model.page != WorkbenchPage::Review {
        render_phase_page_body(frame, area, app, model);
        return;
    }
    render_review_body(frame, area, app, model);
}

/// The Review page: the opt-in depth stack, else the responsive four-pane ring.
fn render_review_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    if let Some(pane) = model.zoom {
        render_zoomed_review_pane(frame, area, app, model, pane);
        return;
    }
    if app.router.workbench().depth_stack() {
        let depth_model = crate::ui_view_models::workbench_depth_model(app);
        super::depth_stack::render_workbench_depth(
            frame,
            area,
            &app.router.workbench().nav(),
            &depth_model,
        );
        return;
    }
    match workbench_layout(area) {
        WorkbenchLayout::FourColumn => render_four_column_body(frame, area, app, model),
        WorkbenchLayout::ReviewGrid => render_review_grid_body(frame, area, app, model),
        WorkbenchLayout::Stacked => render_stacked_body(frame, area, app, model),
        WorkbenchLayout::ShortReview => render_short_review_body(frame, area, app, model),
    }
}

fn render_zoomed_review_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
    pane: WorkbenchPane,
) {
    match pane {
        WorkbenchPane::Source => render_source(frame, area, app, model),
        WorkbenchPane::Center => render_center(frame, area, app, model),
        WorkbenchPane::Findings => render_review_queue_pane(frame, area, &model.review_queue, true),
        WorkbenchPane::Details => render_detail_pane(frame, area, app, model),
    }
}

fn render_phase_page_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    match model.page {
        WorkbenchPage::Terrain => render_terrain_body(frame, area, app, model),
        WorkbenchPage::Coverage => render_single_page_pane(
            frame,
            area,
            "HUNT CONTROL",
            hunt_control_lines(app, area.width.saturating_sub(2) as usize),
            app,
            model,
        ),
        WorkbenchPage::Review => {}
        WorkbenchPage::Ship => render_ship_body(frame, area, app, model),
    }
}

fn render_terrain_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    if area.width < REVIEW_GRID_MIN_WIDTH {
        render_compact_terrain(frame, area, app, model);
        return;
    }
    if area.width < FOUR_COLUMN_MIN_WIDTH {
        render_terrain_grid(frame, area, app, model);
        return;
    }
    render_terrain_columns(frame, area, app, model);
}

fn render_terrain_grid(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let panes = three_pane_grid_areas(area);
    render_page_pane(
        frame,
        panes[0],
        "AIM - ATTACK SURFACE",
        terrain_attack_surface_lines(app, panes[0].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        panes[1],
        "DFD / AIM",
        terrain_visual_lines(app, panes[1].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        panes[2],
        "SEEDS & MATERIALS",
        terrain_material_lines(app, panes[2].width.saturating_sub(2) as usize),
        app,
        model,
    );
}

fn render_compact_terrain(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let width = area.width.saturating_sub(2) as usize;
    render_single_page_pane(
        frame,
        area,
        "AIM",
        combined_page_lines([
            terrain_attack_surface_lines(app, width),
            terrain_visual_lines(app, width),
            terrain_material_lines(app, width),
        ]),
        app,
        model,
    );
}

fn render_terrain_columns(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(38),
            Constraint::Percentage(32),
            Constraint::Percentage(30),
        ])
        .split(area);
    render_page_pane(
        frame,
        cols[0],
        "AIM - ATTACK SURFACE",
        terrain_attack_surface_lines(app, cols[0].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        cols[1],
        "DFD / AIM",
        terrain_visual_lines(app, cols[1].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        cols[2],
        "SEEDS & MATERIALS",
        terrain_material_lines(app, cols[2].width.saturating_sub(2) as usize),
        app,
        model,
    );
}

fn render_ship_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    if area.width < REVIEW_GRID_MIN_WIDTH {
        render_compact_ship(frame, area, app, model);
        return;
    }
    if area.width < FOUR_COLUMN_MIN_WIDTH {
        render_ship_grid(frame, area, app, model);
        return;
    }
    render_ship_columns(frame, area, app, model);
}

fn render_ship_grid(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    let panes = three_pane_grid_areas(area);
    render_page_pane(
        frame,
        panes[0],
        "EXPLOIT CHAINS",
        ship_chain_lines(app, panes[0].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        panes[1],
        "PATCH QUEUE",
        ship_patch_lines(app, panes[1].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        panes[2],
        "EXPORT",
        ship_export_lines(app, panes[2].width.saturating_sub(2) as usize),
        app,
        model,
    );
}

fn three_pane_grid_areas(area: Rect) -> [Rect; 3] {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
        .split(area);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(columns[1]);
    [columns[0], right[0], right[1]]
}

fn render_compact_ship(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let width = area.width.saturating_sub(2) as usize;
    render_single_page_pane(
        frame,
        area,
        "FIX/REPORT",
        combined_page_lines([
            ship_chain_lines(app, width),
            ship_patch_lines(app, width),
            ship_export_lines(app, width),
        ]),
        app,
        model,
    );
}

fn render_ship_columns(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(36),
            Constraint::Percentage(32),
            Constraint::Percentage(32),
        ])
        .split(area);
    render_page_pane(
        frame,
        cols[0],
        "EXPLOIT CHAINS",
        ship_chain_lines(app, cols[0].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        cols[1],
        "PATCH QUEUE",
        ship_patch_lines(app, cols[1].width.saturating_sub(2) as usize),
        app,
        model,
    );
    render_page_pane(
        frame,
        cols[2],
        "EXPORT",
        ship_export_lines(app, cols[2].width.saturating_sub(2) as usize),
        app,
        model,
    );
}

fn render_single_page_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    render_page_pane(frame, area, title, lines, app, model);
}

fn render_page_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    render_pane(
        frame,
        area,
        title,
        lines,
        model.focus == WorkbenchPane::Center,
        app.router.workbench().scroll().get(WorkbenchPane::Center),
    );
}

fn combined_page_lines<const N: usize>(groups: [Vec<Line<'static>>; N]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, group) in groups.into_iter().enumerate() {
        if index > 0 {
            lines.push(blank());
        }
        lines.extend(group);
    }
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkbenchLayout {
    FourColumn,
    ReviewGrid,
    Stacked,
    ShortReview,
}

fn workbench_layout(area: Rect) -> WorkbenchLayout {
    if area.width >= FOUR_COLUMN_MIN_WIDTH {
        return WorkbenchLayout::FourColumn;
    }
    if area.width >= REVIEW_GRID_MIN_WIDTH {
        return WorkbenchLayout::ReviewGrid;
    }
    if area.height >= STACKED_MIN_BODY_HEIGHT {
        return WorkbenchLayout::Stacked;
    }
    WorkbenchLayout::ShortReview
}

fn render_four_column_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let widths = four_column_widths(area.width);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(widths.source),
            Constraint::Length(widths.center),
            Constraint::Length(widths.findings),
            Constraint::Min(widths.details_min),
        ])
        .split(area);
    render_source(frame, cols[0], app, model);
    render_center(frame, cols[1], app, model);
    render_review_queue_pane(
        frame,
        cols[2],
        &model.review_queue,
        model.focus == WorkbenchPane::Findings,
    );
    render_detail_pane(frame, cols[3], app, model);
}

fn render_review_grid_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);
    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(cols[0]);
    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(cols[1]);
    render_source(frame, left_rows[0], app, model);
    render_review_queue_pane(
        frame,
        left_rows[1],
        &model.review_queue,
        model.focus == WorkbenchPane::Findings,
    );
    render_center(frame, right_rows[0], app, model);
    render_detail_pane(frame, right_rows[1], app, model);
}

fn render_stacked_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(stacked_constraints())
        .split(area);
    render_borderless_section(
        frame,
        rows[0],
        &model.center.title,
        center_pane_lines(app, &model.center, rows[0].width as usize),
        pane_scroll(app, model, WorkbenchPane::Center),
    );
    render_findings_section(
        frame,
        rows[1],
        &model.review_queue.header,
        &model.review_queue,
        model.focus == WorkbenchPane::Findings,
    );
    render_borderless_section(
        frame,
        rows[2],
        &detail_pane_title(&model.right_detail),
        detail_pane_lines(
            &model.right_detail,
            rows[2].width as usize,
            report_command(model),
        ),
        pane_scroll(app, model, WorkbenchPane::Details),
    );
}

fn render_short_review_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);
    let findings_title = format!(
        "REVIEW QUEUE {} · 2/4 panes",
        model.review_queue.visible_count
    );
    render_review_queue_pane_with_title(
        frame,
        rows[0],
        &findings_title,
        &model.review_queue,
        model.focus == WorkbenchPane::Findings,
    );
    render_detail_pane(frame, rows[1], app, model);
}

fn stacked_constraints() -> [Constraint; 3] {
    [
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ]
}

fn render_source(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    render_pane(
        frame,
        area,
        &pane_title(
            &source_title(&model.left),
            model.focus == WorkbenchPane::Source,
        ),
        source_pane_lines(&model.left, area.width.saturating_sub(2) as usize),
        model.focus == WorkbenchPane::Source,
        pane_scroll(app, model, WorkbenchPane::Source),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FourColumnWidths {
    source: u16,
    center: u16,
    findings: u16,
    details_min: u16,
}

/// Prioritize the review path: SOURCE stays compact, FINDINGS keeps proof
/// context visible, CENTER remains useful, and DETAILS gets enough width to
/// wrap title/evidence instead of clipping it.
fn four_column_widths(total: u16) -> FourColumnWidths {
    let source = (total * 14 / 100).clamp(18, 32);
    let findings = (total * 34 / 100).clamp(44, 78);
    let mut center = (total * 27 / 100).clamp(36, 72);
    let details_min = 36;
    let fixed = source + findings + center;
    if fixed + details_min > total {
        let reducible = center.saturating_sub(24);
        let needed = fixed + details_min - total;
        center = center.saturating_sub(needed.min(reducible));
    }
    FourColumnWidths {
        source,
        center,
        findings,
        details_min,
    }
}

fn pane_scroll(app: &ShellApp, _model: &WorkbenchViewModel, pane: WorkbenchPane) -> u16 {
    app.router.workbench().scroll().get(pane)
}

fn render_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    focused: bool,
    scroll: u16,
) {
    let block = bordered_block(title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let scroll = clamped_paragraph_scroll(scroll, lines.len(), inner.height);
    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner);
}

fn bordered_block(title: &str, focused: bool) -> Block<'static> {
    cockpit_pane_block(
        Line::from(Span::styled(
            title.to_string(),
            cockpit_title_style(focused),
        )),
        focused,
    )
}

fn center_bordered_block(center: &WorkbenchCenter, focused: bool, width: u16) -> Block<'static> {
    cockpit_pane_block(
        Line::from(center_title_spans(center, focused, width)),
        focused,
    )
}

fn center_title_spans(center: &WorkbenchCenter, focused: bool, width: u16) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (index, tab) in center.tabs.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" │ ".to_string(), theme::subtle()));
        }
        spans.push(center_tab_span(tab, focused));
    }
    append_center_context(&mut spans, center, width);
    spans
}

fn center_tab_span(tab: &WorkbenchCenterTab, focused: bool) -> Span<'static> {
    let mut label = tab.label.to_string();
    if tab.empty {
        label.push('·');
    }
    let style = if tab.active {
        theme::label()
    } else if tab.empty {
        theme::subtle()
    } else if focused {
        theme::muted()
    } else {
        theme::muted()
    };
    Span::styled(format!(" {label} "), style)
}

fn append_center_context(spans: &mut Vec<Span<'static>>, center: &WorkbenchCenter, width: u16) {
    let Some(context) = &center.context else {
        return;
    };
    let used = center_tabs_width(&center.tabs);
    let available = (width as usize).saturating_sub(used + 6);
    if available < 8 {
        return;
    }
    spans.push(Span::styled(" ── ".to_string(), theme::subtle()));
    spans.push(Span::styled(fit(context, available), theme::muted()));
}

fn center_tabs_width(tabs: &[WorkbenchCenterTab]) -> usize {
    tabs.iter()
        .map(|tab| tab.label.len() + usize::from(tab.empty) + 2)
        .sum::<usize>()
        + tabs.len().saturating_sub(1) * 3
}

fn render_center(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, model: &WorkbenchViewModel) {
    let focused = model.focus == WorkbenchPane::Center;
    let block = center_bordered_block(&model.center, focused, area.width);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if render_center_widget(frame, inner, app, &model.center) {
        return;
    }
    render_center_lines(frame, inner, app, model);
}

fn render_center_widget(
    frame: &mut Frame<'_>,
    inner: Rect,
    app: &ShellApp,
    center: &WorkbenchCenter,
) -> bool {
    if inner.width < 24 || inner.height < 8 {
        return false;
    }
    match center.active_mode {
        crate::app::WorkbenchCenterMode::Dfd => {
            frame.render_widget(
                DfdDiagram {
                    model: dfd_model(app),
                },
                inner,
            );
            true
        }
        crate::app::WorkbenchCenterMode::Chain => {
            frame.render_widget(
                TreeDiagram {
                    model: attack_tree(app),
                },
                inner,
            );
            true
        }
        _ => false,
    }
}

fn render_center_lines(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let lines = center_pane_lines(app, &model.center, area.width as usize);
    let scroll = clamped_paragraph_scroll(
        pane_scroll(app, model, WorkbenchPane::Center),
        lines.len(),
        area.height,
    );
    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn render_detail_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &WorkbenchViewModel,
) {
    let title = pane_title(
        &detail_pane_title(&model.right_detail),
        model.focus == WorkbenchPane::Details,
    );
    render_pane(
        frame,
        area,
        &title,
        detail_pane_lines(
            &model.right_detail,
            area.width as usize,
            report_command(model),
        ),
        model.focus == WorkbenchPane::Details,
        pane_scroll(app, model, WorkbenchPane::Details),
    );
}

fn detail_pane_title(detail: &Option<crate::ui_view_models::FindingDetailModel>) -> String {
    detail
        .as_ref()
        .map(detail_title)
        .unwrap_or_else(|| "DETAILS".to_string())
}

fn detail_title(detail: &crate::ui_view_models::FindingDetailModel) -> String {
    let alias = detail.alias.as_deref().unwrap_or("selected");
    format!(
        "{alias} · {} · {}",
        detail.severity_label.to_uppercase(),
        detail.proof_confidence_label
    )
}

fn report_command(model: &WorkbenchViewModel) -> Option<&str> {
    model.report_cta.as_ref().map(|cta| cta.verb.as_ref())
}

fn render_review_queue_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &ReviewQueueModel,
    focused: bool,
) {
    render_review_queue_pane_with_title(frame, area, &model.header, model, focused);
}

fn render_review_queue_pane_with_title(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    model: &ReviewQueueModel,
    focused: bool,
) {
    let block = bordered_block(&pane_title(title, focused), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(review_queue_pane_lines(model, inner)), inner);
}

fn render_findings_section(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    model: &ReviewQueueModel,
    focused: bool,
) {
    let _ = focused;
    render_borderless_section(
        frame,
        area,
        title,
        review_queue_pane_lines(model, section_body_area(area)),
        0,
    );
}

fn render_borderless_section(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    scroll: u16,
) {
    if area.height == 0 {
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(divider(title, area.width)), rows[0]);
    let body = rows[1];
    let scroll = clamped_paragraph_scroll(scroll, lines.len(), body.height);
    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, body);
}

fn section_body_area(area: Rect) -> Rect {
    Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    }
}

fn pane_title(title: &str, focused: bool) -> String {
    let _ = focused;
    title.to_string()
}

fn clamped_paragraph_scroll(scroll: u16, line_count: usize, viewport_height: u16) -> u16 {
    let visible = viewport_height as usize;
    let max_scroll = line_count.saturating_sub(visible);
    scroll.min(max_scroll.min(u16::MAX as usize) as u16)
}

// ── top bar ────────────────────────────────────────────────────────────────

fn top_bar_lines(
    top: &WorkbenchTopBar,
    hints: &[WorkbenchHint],
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![identity_line(top, width)];
    lines.extend(journey_lines(top, width));
    lines.push(command_hint_line(hints, width));
    lines
}

fn identity_line(top: &WorkbenchTopBar, width: usize) -> Line<'static> {
    let mut spans = Vec::new();
    let mut used = 0;
    for (text, style) in identity_atoms(top) {
        push_top_atom(&mut spans, &mut used, width, text, style);
    }
    Line::from(spans)
}

fn identity_atoms(top: &WorkbenchTopBar) -> Vec<(String, ratatui::style::Style)> {
    let live_atom = if top.live {
        ("● LIVE".to_string(), theme::success())
    } else {
        ("○ idle".to_string(), theme::subtle())
    };
    let mut atoms = vec![
        (top.brand.to_string(), theme::heading()),
        (format!("target:{}", top.project), theme::label()),
        (
            format!("page:{}", top.page.title().to_ascii_lowercase()),
            theme::label(),
        ),
        live_atom,
    ];
    atoms.extend(identity_phase_atom(top));
    atoms.push((format!("modules:{}", top.target), theme::muted()));
    atoms
}

fn identity_phase_atom(top: &WorkbenchTopBar) -> Option<(String, ratatui::style::Style)> {
    if !top.phase_rail.is_empty() {
        return None;
    }
    top.phase
        .as_ref()
        .map(|phase| (format!("phase:{phase}"), theme::muted()))
}

fn push_top_atom(
    spans: &mut Vec<Span<'static>>,
    used: &mut usize,
    width: usize,
    text: String,
    style: ratatui::style::Style,
) -> bool {
    let separator_width = usize::from(*used > 0) * 3;
    let atom_width = text.chars().count();
    if used.saturating_add(separator_width + atom_width) > width {
        return false;
    }
    if *used > 0 {
        spans.push(Span::styled(" · ", theme::subtle()));
    }
    spans.push(Span::styled(text, style));
    *used += separator_width + atom_width;
    true
}

fn command_hint_line(hints: &[WorkbenchHint], width: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for hint in hints {
        let atom = format!(
            "{}{} {}",
            hint_prefix(hint.verb.as_ref()),
            hint.verb,
            hint.label
        );
        let atom_width = atom.chars().count();
        let separator = if used > 1 { 3 } else { 0 };
        if used + separator + atom_width > width {
            continue;
        }
        if separator > 0 {
            spans.push(Span::raw(" · "));
        }
        spans.push(Span::styled(atom, theme::muted()));
        used += separator + atom_width;
    }
    Line::from(spans)
}

fn hint_prefix(verb: &str) -> &'static str {
    if verb.chars().count() == 1 {
        "press "
    } else {
        "type "
    }
}

fn journey_lines(top: &WorkbenchTopBar, width: usize) -> Vec<Line<'static>> {
    if top.phase_rail.is_empty() {
        return Vec::new();
    }
    let mut lines = phase_rail_line(&top.phase_rail, width)
        .into_iter()
        .collect::<Vec<_>>();
    lines.extend(phase_next_lines(top.phase_next_summary.as_deref(), width));
    lines
}

fn phase_rail_line(statuses: &[JourneyPhaseStatus], width: usize) -> Option<Line<'static>> {
    let rail_text = statuses
        .iter()
        .map(|status| format!("{}{}", status.phase_label, status.state_symbol))
        .collect::<Vec<_>>()
        .join(" · ");
    if width < 100 || rail_text.chars().count() >= width {
        return None;
    }
    let mut spans = vec![Span::raw(" ")];
    append_phase_rail_spans(&mut spans, statuses);
    Some(Line::from(spans))
}

fn phase_next_lines(summary: Option<&str>, width: usize) -> Vec<Line<'static>> {
    let Some(summary) = summary else {
        return Vec::new();
    };
    wrap_text(
        compact_next_summary(summary, width),
        width.saturating_sub(8).max(16),
    )
    .into_iter()
    .enumerate()
    .map(|(index, chunk)| next_action_line(index, chunk))
    .collect()
}

fn compact_next_summary(summary: &str, width: usize) -> &str {
    if width >= 100 {
        return summary;
    }
    summary
        .split_once(" — ")
        .map(|(head, _)| head)
        .unwrap_or(summary)
}

fn next_action_line(index: usize, chunk: String) -> Line<'static> {
    let lead = if index == 0 {
        Span::styled(" ▸ NEXT ", theme::warn())
    } else {
        Span::raw("        ")
    };
    Line::from(vec![lead, Span::styled(chunk, theme::primary())])
}

fn append_phase_rail_spans(spans: &mut Vec<Span<'static>>, statuses: &[JourneyPhaseStatus]) {
    for (index, status) in statuses.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        let style = journey_phase_tone_style(status.tone);
        spans.push(Span::styled(status.phase_label.to_string(), style));
        spans.push(Span::styled(status.state_symbol.to_string(), style));
    }
}

// ── plain / non-TTY path ─────────────────────────────────────────────────────

/// Line-based projection of the Workbench for plain/non-TTY output. Text only:
/// section dividers stand in for the bordered panes (no box-drawing dependency
/// for the layout structure); center content reuses the same lines.
pub(crate) fn workbench_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = workbench_view_model(app);
    let mut lines = top_bar_lines(
        &model.top_bar,
        &model.command_bar_hints,
        area.width as usize,
    );
    lines.push(blank());
    if model.page != WorkbenchPage::Review {
        append_phase_page_plain_lines(&mut lines, app, &model, area);
    } else if app.router.workbench().depth_stack() {
        let depth_model = crate::ui_view_models::workbench_depth_model(app);
        lines.extend(super::depth_stack::workbench_depth_lines(
            &app.router.workbench().nav(),
            &depth_model,
            area.width,
        ));
    } else {
        append_review_plain_lines(&mut lines, app, &model, area);
    }
    lines
}

/// The four-pane review plain projection (SOURCE / CENTER / FINDINGS / DETAILS
/// dividers), used when the depth stack is off.
fn append_review_plain_lines(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    model: &WorkbenchViewModel,
    area: Rect,
) {
    lines.push(divider(
        &pane_title(
            &source_title(&model.left),
            model.focus == WorkbenchPane::Source,
        ),
        area.width,
    ));
    lines.extend(source_pane_lines(&model.left, area.width as usize));
    lines.push(blank());
    lines.push(divider(
        &pane_title(&model.center.title, model.focus == WorkbenchPane::Center),
        area.width,
    ));
    lines.extend(center_pane_lines(app, &model.center, area.width as usize));
    lines.push(blank());
    lines.push(divider(
        &pane_title(
            &model.review_queue.header,
            model.focus == WorkbenchPane::Findings,
        ),
        area.width,
    ));
    lines.extend(review_queue_pane_lines(&model.review_queue, area));
    lines.push(blank());
    append_detail_plain_lines(lines, model, area);
}

fn append_phase_page_plain_lines(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    model: &WorkbenchViewModel,
    area: Rect,
) {
    let width = area.width as usize;
    match model.page {
        WorkbenchPage::Terrain => {
            lines.push(divider("AIM - ATTACK SURFACE", area.width));
            lines.extend(terrain_attack_surface_lines(app, width));
            lines.push(blank());
            lines.push(divider("DFD / AIM", area.width));
            lines.extend(terrain_visual_lines(app, width));
            lines.push(blank());
            lines.push(divider("SEEDS & MATERIALS", area.width));
            lines.extend(terrain_material_lines(app, width));
        }
        WorkbenchPage::Coverage => {
            lines.push(divider("HUNT CONTROL", area.width));
            lines.extend(hunt_control_lines(app, width));
        }
        WorkbenchPage::Review => {}
        WorkbenchPage::Ship => {
            lines.push(divider("EXPLOIT CHAINS", area.width));
            lines.extend(ship_chain_lines(app, width));
            lines.push(blank());
            lines.push(divider("PATCH QUEUE", area.width));
            lines.extend(ship_patch_lines(app, width));
            lines.push(blank());
            lines.push(divider("EXPORT", area.width));
            lines.extend(ship_export_lines(app, width));
        }
    }
}

fn append_detail_plain_lines(
    lines: &mut Vec<Line<'static>>,
    model: &WorkbenchViewModel,
    area: Rect,
) {
    lines.push(divider(
        &pane_title("DETAILS", model.focus == WorkbenchPane::Details),
        area.width,
    ));
    lines.extend(detail_pane_lines(
        &model.right_detail,
        area.width as usize,
        report_command(model),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_column_layout_can_fit_full_finding_meta_on_wide_terminals() {
        let widths = four_column_widths(260);

        assert!(
            widths.findings.saturating_sub(2) >= 60,
            "findings pane inner width should fit dense worklist rows: {widths:?}"
        );
    }

    #[test]
    fn common_widths_use_review_grid_instead_of_short_columns() {
        assert_eq!(
            workbench_layout(Rect::new(0, 0, 120, 30)),
            WorkbenchLayout::ReviewGrid
        );
    }

    #[test]
    fn very_wide_terminals_use_four_columns() {
        assert_eq!(
            workbench_layout(Rect::new(0, 0, 150, 30)),
            WorkbenchLayout::FourColumn
        );
    }

    #[test]
    fn common_width_phase_pages_use_two_column_grid() {
        let panes = three_pane_grid_areas(Rect::new(0, 0, 120, 30));
        assert_eq!(panes[0].height, 30);
        assert_eq!(panes[1].x, panes[2].x);
        assert_eq!(panes[1].width, panes[2].width);
        assert_eq!(panes[1].height + panes[2].height, 30);
        assert!(panes.iter().all(|pane| pane.width >= 50));
    }
}
