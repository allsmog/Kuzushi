use super::*;
use crate::app::WorkbenchSurfaceScroll;
use crate::ui_view_models::{
    LayoutDensity, PhaseCockpitBody, PhaseCockpitModel, PhasePresentationPlan, PhaseSurfaceId,
    SurfaceRole,
};
use ratatui::layout::Rect;
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::{Paragraph, Widget, Wrap};

mod confirm;
mod fix;
mod header;
mod hunt;
mod map;
mod scan;

pub(in crate::renderer::views) use header::phase_header_lines;

#[derive(Debug, Clone, Copy)]
pub(in crate::renderer::views) struct PhaseRenderState<'a> {
    pub(super) focus: Option<PhaseSurfaceId>,
    /// When set, the page renderer paints exactly this surface into the given
    /// rect; when `None`, the page falls back to its own internal grid.
    pub(super) surface: Option<PhaseSurfaceId>,
    /// The composition role of `surface` — canvas and drawer regions render
    /// with screen-specific chrome instead of the classic pane block.
    pub(super) role: SurfaceRole,
    pub(super) scroll: &'a WorkbenchSurfaceScroll,
    pub(super) density: LayoutDensity,
}

impl<'a> PhaseRenderState<'a> {
    pub(super) fn workbench(app: &'a ShellApp, plan: &PhasePresentationPlan) -> Self {
        let route = app.router.workbench();
        Self {
            focus: (plan.density != LayoutDensity::Guided).then_some(plan.effective_focus),
            surface: route.zoom().surface(),
            role: SurfaceRole::Standard,
            scroll: route.scroll(),
            density: plan.density,
        }
    }

    pub(super) fn focused(self, surface: PhaseSurfaceId) -> bool {
        self.focus == Some(surface)
    }

    pub(super) fn scroll(self, surface: PhaseSurfaceId) -> u16 {
        self.scroll.get(surface)
    }
}

pub(in crate::renderer::views) fn render_phase_cockpit_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &PhaseCockpitModel,
    plan: &PhasePresentationPlan,
    state: PhaseRenderState,
) {
    let _ = area;
    for surface in &plan.surfaces {
        let surface_state = PhaseRenderState {
            surface: Some(surface.id),
            role: plan.composition.role_of(surface.id),
            ..state
        };
        match &model.body {
            PhaseCockpitBody::Map(map) => {
                map::render(frame, surface.rect, app, map, &model.header, surface_state)
            }
            PhaseCockpitBody::Scan(scan) => scan::render(frame, surface.rect, scan, surface_state),
            PhaseCockpitBody::Review(hunt) => {
                hunt::render(frame, surface.rect, app, hunt, surface_state)
            }
            PhaseCockpitBody::Prove(confirm) => {
                confirm::render(frame, surface.rect, confirm, surface_state)
            }
            PhaseCockpitBody::Fix(fix) => fix::render(frame, surface.rect, fix, surface_state),
        }
    }
}

pub(in crate::renderer::views) fn phase_cockpit_plain_lines(
    app: &ShellApp,
    model: &PhaseCockpitModel,
    width: usize,
) -> Vec<Line<'static>> {
    match &model.body {
        PhaseCockpitBody::Map(map) => map::plain_lines(app, map, &model.header, width),
        PhaseCockpitBody::Scan(scan) => scan::plain_lines(scan, width),
        PhaseCockpitBody::Review(hunt) => hunt::plain_lines(hunt, width),
        PhaseCockpitBody::Prove(confirm) => confirm::plain_lines(confirm, width),
        PhaseCockpitBody::Fix(fix) => fix::plain_lines(fix, width),
    }
}

pub(super) fn render_lines_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: impl Into<String>,
    lines: Vec<Line<'static>>,
    surface: PhaseSurfaceId,
    state: PhaseRenderState,
) {
    let focused = state.focused(surface);
    let block = cockpit_pane_block(
        Line::from(Span::styled(title.into(), cockpit_title_style(focused))),
        focused,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let visual_rows = wrapped_line_count(&lines, inner.width);
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let scroll = clamped_scroll(state.scroll(surface), visual_rows, inner.height);
    frame.render_widget(paragraph.scroll((scroll, 0)), inner);
}

pub(super) fn render_diagram_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &'static str,
    surface: PhaseSurfaceId,
    state: PhaseRenderState,
    diagram: impl Widget,
) {
    let focused = state.focused(surface);
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

pub(super) fn selection_disclosure_lines(
    disclosure: Option<&crate::ui_view_models::SelectionDisclosureModel>,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(disclosure) = disclosure else {
        return Vec::new();
    };
    vec![
        Line::styled(
            fit(&format!("⚠ {}", disclosure.message), width),
            theme::warn(),
        ),
        Line::from(vec![
            Span::styled(
                fit(
                    &format!("filter:{} · ", disclosure.filter),
                    width.saturating_sub(disclosure.reveal_command.len() + 10),
                ),
                theme::muted(),
            ),
            Span::styled(
                format!("▸ {} reveal", disclosure.reveal_command),
                theme::accent(),
            ),
        ]),
    ]
}

fn clamped_scroll(scroll: u16, rows: usize, viewport: u16) -> u16 {
    scroll.min(
        rows.saturating_sub(viewport as usize)
            .min(u16::MAX as usize) as u16,
    )
}

fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> usize {
    let width = width.max(1) as usize;
    lines
        .iter()
        .map(|line| wrap_text(&line.to_string(), width).len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_unicode_rows_expand_the_scroll_extent() {
        let lines = vec![Line::from(
            "touched: src/認証/very-long-remediation-target-with-emoji-🔐.rs",
        )];

        let rows = wrapped_line_count(&lines, 18);

        assert!(rows >= 4, "expected visual wrapping, got {rows} row(s)");
        assert!(clamped_scroll(u16::MAX, rows, 2) >= 2);
    }
}
