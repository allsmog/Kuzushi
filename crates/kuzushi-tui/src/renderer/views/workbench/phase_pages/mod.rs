use super::*;
use crate::app::{WorkbenchPage, WorkbenchPane, WorkbenchPaneScroll};
use crate::ui_view_models::{PhaseCockpitBody, PhaseCockpitModel};
use kuzushi_core::WorkflowPhase;
use ratatui::layout::Rect;
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::{Paragraph, Widget, Wrap};

mod confirm;
mod fix;
mod header;
mod hunt;
mod map;

pub(in crate::renderer::views) use header::phase_header_lines;

#[derive(Debug, Clone, Copy)]
pub(in crate::renderer::views) struct PhaseRenderState {
    pub(super) focus: Option<WorkbenchPane>,
    pub(super) zoom: Option<WorkbenchPane>,
    pub(super) scroll: WorkbenchPaneScroll,
}

impl PhaseRenderState {
    pub(super) fn workbench(app: &ShellApp, page: WorkbenchPage) -> Self {
        let route = app.router.workbench();
        let raw_focus = route.focus();
        let viewport = app.viewport();
        let pane_order = page.pane_order_for_viewport(viewport.columns, viewport.rows);
        let focus = pane_order
            .contains(&raw_focus)
            .then_some(raw_focus)
            .unwrap_or_else(|| page.primary_pane_for_viewport(viewport.columns, viewport.rows));
        let zoom = route.zoom().pane().filter(|pane| pane_order.contains(pane));
        Self {
            focus: Some(focus),
            zoom,
            scroll: route.scroll(),
        }
    }

    pub(super) fn focused(self, pane: WorkbenchPane) -> bool {
        self.focus == Some(pane)
    }

    pub(super) fn scroll(self, pane: WorkbenchPane) -> u16 {
        self.scroll.get(pane)
    }

    pub(in crate::renderer::views) fn activity() -> Self {
        Self {
            focus: None,
            zoom: None,
            scroll: WorkbenchPaneScroll::default(),
        }
    }
}

pub(in crate::renderer::views) fn render_phase_cockpit_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &PhaseCockpitModel,
    state: PhaseRenderState,
) {
    match &model.body {
        PhaseCockpitBody::Map(map) => map::render(frame, area, map, &model.header, state),
        PhaseCockpitBody::Hunt(hunt) => hunt::render(frame, area, app, hunt, state),
        PhaseCockpitBody::Confirm(confirm) => confirm::render(frame, area, confirm, state),
        PhaseCockpitBody::Fix(fix) => fix::render(frame, area, fix, state),
    }
}

pub(in crate::renderer::views) fn phase_cockpit_plain_lines(
    model: &PhaseCockpitModel,
    width: usize,
) -> Vec<Line<'static>> {
    match &model.body {
        PhaseCockpitBody::Map(map) => map::plain_lines(map, &model.header, width),
        PhaseCockpitBody::Hunt(hunt) => hunt::plain_lines(hunt, width),
        PhaseCockpitBody::Confirm(confirm) => confirm::plain_lines(confirm, width),
        PhaseCockpitBody::Fix(fix) => fix::plain_lines(fix, width),
    }
}

pub(super) fn render_lines_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: impl Into<String>,
    lines: Vec<Line<'static>>,
    pane: WorkbenchPane,
    state: PhaseRenderState,
) {
    let focused = state.focused(pane);
    let block = cockpit_pane_block(
        Line::from(Span::styled(title.into(), cockpit_title_style(focused))),
        focused,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let scroll = clamped_scroll(state.scroll(pane), lines.len(), inner.height);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

pub(super) fn render_diagram_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &'static str,
    pane: WorkbenchPane,
    state: PhaseRenderState,
    diagram: impl Widget,
) {
    let focused = state.focused(pane);
    let block = cockpit_pane_block(
        Line::from(Span::styled(title, cockpit_title_style(focused))),
        focused,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(diagram, inner);
}

pub(super) fn divider_lines(
    title: &str,
    body: Vec<Line<'static>>,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider(title, width as u16)];
    lines.extend(body);
    lines
}

pub(super) fn page_phase(page: WorkbenchPage) -> WorkflowPhase {
    match page {
        WorkbenchPage::Terrain => WorkflowPhase::Map,
        WorkbenchPage::Coverage => WorkflowPhase::Hunt,
        WorkbenchPage::Review => WorkflowPhase::Confirm,
        WorkbenchPage::Ship => WorkflowPhase::Fix,
    }
}

fn clamped_scroll(scroll: u16, rows: usize, viewport: u16) -> u16 {
    scroll.min(
        rows.saturating_sub(viewport as usize)
            .min(u16::MAX as usize) as u16,
    )
}
