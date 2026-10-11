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

pub(in crate::renderer::views) use header::{compact_review_header_lines, phase_header_lines};

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
    let title = title.into();
    let block = cockpit_pane_block(
        Line::from(Span::styled(title.clone(), cockpit_title_style(focused))),
        focused,
    );
    let inner = block.inner(area);
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let visual_rows = paragraph.line_count(inner.width);
    let scroll = clamped_scroll(state.scroll(surface), visual_rows, inner.height);
    let title = scan_scroll_title(&title, surface, visual_rows, scroll, inner);
    frame.render_widget(
        cockpit_pane_block(Line::styled(title, cockpit_title_style(focused)), focused),
        area,
    );
    frame.render_widget(paragraph.scroll((scroll, 0)), inner);
}

fn scan_scroll_title(
    title: &str,
    surface: PhaseSurfaceId,
    rows: usize,
    scroll: u16,
    inner: Rect,
) -> String {
    if surface != PhaseSurfaceId::ScanEngines || rows <= inner.height as usize {
        return title.to_string();
    }
    let first = scroll as usize + 1;
    let last = (scroll as usize + inner.height as usize).min(rows);
    let hint = format!("{first}-{last}/{rows} PgUp/PgDn");
    let title_width = (inner.width as usize).saturating_sub(hint.len() + 1);
    format!("{} {hint}", fit(title, title_width))
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
    let mut lines =
        crate::renderer::shared::text::wrap_text(&format!("⚠ {}", disclosure.message), width)
            .into_iter()
            .map(|line| Line::styled(line, theme::warn()))
            .collect::<Vec<_>>();
    let filter = disclosure
        .filter
        .as_ref()
        .map(|filter| format!("filter:{filter} · "))
        .unwrap_or_default();
    let recovery = format!(
        "{filter}▸ {} {}",
        disclosure.reveal_command, disclosure.reveal_label
    );
    lines.extend(
        crate::renderer::shared::text::wrap_text(&recovery, width)
            .into_iter()
            .map(|line| Line::styled(line, theme::accent())),
    );
    lines
}

fn clamped_scroll(scroll: u16, rows: usize, viewport: u16) -> u16 {
    scroll.min(
        rows.saturating_sub(viewport as usize)
            .min(u16::MAX as usize) as u16,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_disclosure_keeps_identity_and_action_target_when_wrapped() {
        let disclosure = crate::ui_view_models::SelectionDisclosureModel {
            message: "F-0952 pinned outside list; decisions use this detail".into(),
            filter: Some("name:0656".into()),
            reveal_command: "findings".into(),
            reveal_label: "reveal",
        };
        let lines = selection_disclosure_lines(Some(&disclosure), 34);
        let text = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("F-0952 pinned outside list"), "{text}");
        assert!(text.contains("decisions use this detail"), "{text}");
        assert!(lines.iter().all(|line| line.width() <= 34));
    }

    #[test]
    fn historical_disclosure_wraps_the_current_observation_command_without_a_filter_claim() {
        let disclosure = crate::ui_view_models::SelectionDisclosureModel {
            message: "F-0601 shows an earlier observation; decisions stay bound to it".into(),
            filter: None,
            reveal_command: "open F-0601".into(),
            reveal_label: "inspect current",
        };
        for width in [18, 34, 38, 78] {
            let lines = selection_disclosure_lines(Some(&disclosure), width);
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains("open F-0601"), "{text}");
            assert!(text.contains("inspect current"), "{text}");
            assert!(!text.contains("filter:"), "{text}");
            assert!(lines.iter().all(|line| line.width() <= width));
        }
    }

    #[test]
    fn maximum_scroll_reaches_final_row_after_indented_wrapping() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut lines = vec![Line::from(format!("      {}", "x ".repeat(19))); 12];
        lines.push(Line::from("FINAL LINEAGE"));
        let mut terminal = Terminal::new(TestBackend::new(40, 7)).unwrap();
        let mut scroll = WorkbenchSurfaceScroll::default();
        scroll.set(PhaseSurfaceId::ProveResult, u16::MAX);
        let state = PhaseRenderState {
            focus: Some(PhaseSurfaceId::ProveResult),
            surface: Some(PhaseSurfaceId::ProveResult),
            role: SurfaceRole::Standard,
            scroll: &scroll,
            density: LayoutDensity::Guided,
        };
        terminal
            .draw(|frame| {
                render_lines_pane(
                    frame,
                    frame.area(),
                    "RESULT",
                    lines.clone(),
                    PhaseSurfaceId::ProveResult,
                    state,
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..7)
            .map(|y| (0..40).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("FINAL LINEAGE"), "{text}");
    }

    #[test]
    fn wrapped_unicode_rows_expand_the_scroll_extent() {
        let lines = vec![Line::from(
            "touched: src/認証/very-long-remediation-target-with-emoji-🔐.rs",
        )];

        let rows = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .line_count(18);

        assert!(rows >= 4, "expected visual wrapping, got {rows} row(s)");
        assert!(clamped_scroll(u16::MAX, rows, 2) >= 2);
    }

    #[test]
    fn native_engine_overflow_discloses_its_range_and_paging_control() {
        let inner = Rect::new(1, 2, 38, 3);
        let title = scan_scroll_title(
            "RECORDED ENGINE OUTCOMES",
            PhaseSurfaceId::ScanEngines,
            14,
            6,
            inner,
        );
        assert!(title.contains("7-9/14 PgUp/PgDn"), "{title}");
        assert!(title.chars().count() <= 38, "{title}");
        assert_eq!(
            scan_scroll_title("OUTCOMES", PhaseSurfaceId::ScanEngines, 3, 0, inner),
            "OUTCOMES"
        );
    }
}
