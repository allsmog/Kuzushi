use super::*;
use crate::app::WorkbenchPage;
use crate::ui_view_models::{
    phase_presentation_plan, workbench_presentation_snapshot, AttentionMode, EngagementHeaderModel,
    JourneyPhaseStatus, PhaseCockpitModel, PhaseSurfaceId, WorkbenchChromeModel, WorkbenchHint,
    WorkbenchTopBar,
};
use ratatui::layout::Rect;
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::Paragraph;

const MIN_COMPACT_ZOOM_BODY_ROWS: u16 = 4;

/// Render the one canonical phase-native cockpit.
pub(crate) fn render_workbench_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let snapshot = workbench_presentation_snapshot(app);
    render_phase_presentation(frame, area, app, &snapshot.chrome, &snapshot.phase);
}

pub(crate) fn workbench_phase_plan_for_app(
    app: &ShellApp,
    terminal_area: Rect,
) -> Option<crate::ui_view_models::PhasePresentationPlan> {
    if app.shell_view() != crate::ShellView::Workbench {
        return None;
    }
    let area = crate::renderer::workbench_primary_area(app, terminal_area);
    let snapshot = workbench_presentation_snapshot(app);
    let phase = &snapshot.phase;
    let chrome = &snapshot.chrome;
    let question_visible = app.guided_scan_question_model().is_some();
    let mut header = phase.header.clone();
    if question_visible {
        header.result_card = None;
    }
    let lines = workbench_header_lines(
        app,
        &chrome,
        &header,
        area.width as usize,
        area.height as usize,
    );
    let displayed_zoom = displayed_zoom(area, lines.len(), app.router.workbench().zoom().surface());
    let header_rows = lines.len() + usize::from(displayed_zoom.is_some());
    let body = workbench_body_area(area, header_rows);
    workbench_body_is_visible(body).then(|| {
        let route = app.router.workbench();
        phase_presentation_plan(
            &phase.body,
            body,
            Some(route.focus_for(chrome.page)),
            route.zoom().surface(),
            phase_attention_mode(question_visible, &phase),
        )
    })
}

fn render_phase_presentation(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    chrome: &WorkbenchChromeModel,
    phase: &PhaseCockpitModel,
) {
    let question_visible = app.guided_scan_question_model().is_some();
    let top_lines = presentation_header_lines(area, app, chrome, phase, question_visible);
    let requested_zoom = app.router.workbench().zoom().surface();
    let displayed_zoom = displayed_zoom(area, top_lines.len(), requested_zoom);
    let header_rows = top_lines.len() + usize::from(displayed_zoom.is_some());
    let planned_body = workbench_body_area(area, header_rows);
    if !workbench_body_is_visible(planned_body) {
        render_workbench_header(frame, area, top_lines, None);
        return;
    }
    let attention = phase_attention_mode(question_visible, phase);
    let route = app.router.workbench();
    let plan = phase_presentation_plan(
        &phase.body,
        planned_body,
        Some(route.focus_for(chrome.page)),
        requested_zoom,
        attention,
    );
    let displayed_zoom = displayed_zoom.map(|_| plan.effective_focus);
    let body = render_workbench_header(frame, area, top_lines, displayed_zoom);
    if !workbench_body_is_visible(body) {
        return;
    }
    let phase_state = super::phase_pages::PhaseRenderState::workbench(app, &plan);
    super::phase_pages::render_phase_cockpit_body(frame, body, app, phase, &plan, phase_state);
    render_hosted_guided_question(frame, body, app, &plan);
}

/// The Clarify composition: with room, the guided question renders as the
/// dominant centered card in the body below the Guided context strip, and the
/// input surface keeps its plain prompt line.
fn render_hosted_guided_question(
    frame: &mut Frame<'_>,
    body: Rect,
    app: &ShellApp,
    plan: &crate::ui_view_models::PhasePresentationPlan,
) {
    let Some(question) = app.guided_scan_question_model() else {
        return;
    };
    // Must agree with `render_input_surface`'s hosting decision, which
    // measures the rail-reduced body — not the full terminal.
    let (content, _) = crate::renderer::split_context_rail(app, frame.area());
    if !super::guided_question_hosted_in_body(content.width, content.height) {
        return;
    }
    let strip_bottom = plan
        .surfaces
        .iter()
        .map(|surface| surface.rect.bottom())
        .max()
        .unwrap_or(body.y);
    let card_area = Rect::new(
        body.x,
        strip_bottom.saturating_add(1).min(body.bottom()),
        body.width,
        body.bottom()
            .saturating_sub(strip_bottom.saturating_add(1).min(body.bottom())),
    );
    let page = crate::ui_view_models::active_workbench_page(app);
    super::render_guided_question_card(frame, card_area, page, &question);
}

fn presentation_header_lines(
    area: Rect,
    app: &ShellApp,
    chrome: &WorkbenchChromeModel,
    phase: &PhaseCockpitModel,
    question_visible: bool,
) -> Vec<Line<'static>> {
    let mut header = phase.header.clone();
    if question_visible {
        header.result_card = None;
    }
    workbench_header_lines(
        app,
        chrome,
        &header,
        area.width as usize,
        area.height as usize,
    )
}

fn displayed_zoom(
    area: Rect,
    header_line_count: usize,
    requested_zoom: Option<PhaseSurfaceId>,
) -> Option<PhaseSurfaceId> {
    requested_zoom.filter(|_| {
        area.height
            .saturating_sub(header_line_count as u16)
            .saturating_sub(1)
            >= MIN_COMPACT_ZOOM_BODY_ROWS
    })
}

fn phase_attention_mode(question_visible: bool, phase: &PhaseCockpitModel) -> AttentionMode {
    if question_visible {
        AttentionMode::GuidedQuestion
    } else if phase
        .header
        .result_card
        .as_ref()
        .is_some_and(|card| card.emphasis == crate::PhaseResultEmphasis::DominantDecision)
    {
        AttentionMode::ResultReady
    } else {
        AttentionMode::Normal
    }
}

fn workbench_body_is_visible(area: Rect) -> bool {
    area.width >= 8 && area.height >= 3
}

fn render_workbench_header(
    frame: &mut Frame<'_>,
    area: Rect,
    mut top_lines: Vec<Line<'static>>,
    displayed_zoom: Option<PhaseSurfaceId>,
) -> Rect {
    paint_cinematic_background(frame.buffer_mut(), area);
    paint_cinematic_scanlines(frame.buffer_mut(), area);
    if let Some(surface) = displayed_zoom {
        top_lines.push(zoom_status_line(surface));
    }
    let body = workbench_body_area(area, top_lines.len());
    let header = Rect::new(area.x, area.y, area.width, body.y.saturating_sub(area.y));
    frame.render_widget(Paragraph::new(top_lines), header);
    body
}

fn workbench_body_area(area: Rect, header_line_count: usize) -> Rect {
    let header_rows = (header_line_count as u16).min(area.height);
    Rect::new(
        area.x,
        area.y.saturating_add(header_rows),
        area.width,
        area.height.saturating_sub(header_rows),
    )
}

fn workbench_header_lines(
    app: &ShellApp,
    chrome: &WorkbenchChromeModel,
    phase_header: &EngagementHeaderModel,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    if app.prove_detail_owns_controls() {
        return Vec::new();
    }
    if app.target().is_none() {
        return top_bar_lines(&chrome.top_bar, &chrome.command_bar_hints, width);
    }
    if crate::ui_view_models::compact_phase_reading(app, app.viewport().rows)
        && phase_header.result_card.is_none()
    {
        return super::phase_pages::compact_review_header_lines(phase_header, width);
    }
    super::phase_pages::phase_header_lines(phase_header, &chrome.command_bar_hints, width, height)
}

fn zoom_status_line(surface: PhaseSurfaceId) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ▸ ZOOM ", theme::warn()),
        Span::styled(phase_surface_zoom_label(surface), theme::primary()),
        Span::styled(" · Tab pane · Z restore cockpit", theme::muted()),
    ])
}

fn phase_surface_zoom_label(surface: PhaseSurfaceId) -> &'static str {
    match surface {
        PhaseSurfaceId::MapReadiness => "PROJECT CONTEXT",
        PhaseSurfaceId::MapAttackSurface => "ATTACK SURFACE",
        PhaseSurfaceId::MapHotModules => "HOT MODULES",
        PhaseSurfaceId::MapDfd | PhaseSurfaceId::FixDfd => "DFD",
        PhaseSurfaceId::ScanScope => "SCOPE / PLAN",
        PhaseSurfaceId::ScanEngines => "ENGINE OUTCOMES",
        PhaseSurfaceId::ScanDelta => "FINDING DELTA",
        PhaseSurfaceId::ScanReceipt => "SCAN RECEIPT",
        PhaseSurfaceId::ReviewQueue => "FINDINGS",
        PhaseSurfaceId::ReviewDetail => "SELECTED FINDING",
        PhaseSurfaceId::ReviewNextPlan => "NEXT INVESTIGATION PLAN",
        PhaseSurfaceId::ReviewChains => "ATTACK CHAINS",
        PhaseSurfaceId::ProveStatus => "STATUS / NEXT",
        PhaseSurfaceId::ProveEvidence => "EVIDENCE",
        PhaseSurfaceId::ProveLadder => "PROOF LADDER",
        PhaseSurfaceId::ProveReceipt => "PROOF",
        PhaseSurfaceId::ProveNextAction => "NEXT ACTION",
        PhaseSurfaceId::ProveInvestigation => "INVESTIGATION PLAN",
        PhaseSurfaceId::ProveResult => "PROVE RESULT",
        PhaseSurfaceId::ProveTrace | PhaseSurfaceId::ReviewTrace => "TRACE",
        PhaseSurfaceId::FixCandidate => "FIX STATUS",
        PhaseSurfaceId::FixAttackTree => "ATTACK TREE",
        PhaseSurfaceId::FixRemediation => "REMEDIATION",
        PhaseSurfaceId::FixVerification => "VERIFICATION",
    }
}

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
    let live_atom = liveness_atom(top.liveness);
    let mut atoms = vec![
        (top.brand.to_string(), theme::heading()),
        (
            format!("VIEW {}", top.page.title()),
            page_mode_style(top.page),
        ),
        (format!("target:{}", top.project), theme::label()),
        live_atom,
    ];
    atoms.extend(identity_phase_atom(top));
    atoms.push((format!("modules:{}", top.target), theme::muted()));
    atoms
}

fn liveness_atom(liveness: crate::ui_view_models::WorkLiveness) -> (String, ratatui::style::Style) {
    match liveness {
        crate::ui_view_models::WorkLiveness::Live => ("● LIVE".to_string(), theme::success()),
        // External writers (another session, a detached campaign) are
        // changing workspace state: not our work, but not idle either.
        crate::ui_view_models::WorkLiveness::ExternalSync => {
            ("◌ workspace sync".to_string(), theme::warn())
        }
        crate::ui_view_models::WorkLiveness::Idle => ("○ idle".to_string(), theme::subtle()),
    }
}

fn page_mode_style(page: WorkbenchPage) -> ratatui::style::Style {
    match page {
        WorkbenchPage::Map => theme::mode_map(),
        WorkbenchPage::Scan => theme::mode_scan(),
        WorkbenchPage::Review => theme::mode_review(),
        WorkbenchPage::Prove => theme::mode_prove(),
        WorkbenchPage::Fix => theme::mode_fix(),
    }
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
    let atom_width = crate::renderer::shared::text::display_width(&text);
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
        let atom_width = crate::renderer::shared::text::display_width(&atom);
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
        .map(|status| format!("{}{}", status.phase_label, status.navigation_symbol()))
        .collect::<Vec<_>>()
        .join(" · ");
    if width < 100 || crate::renderer::shared::text::display_width(&rail_text) >= width {
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
        spans.push(Span::styled(status.navigation_symbol().to_string(), style));
    }
}

/// Line-based projection of the same canonical cockpit for plain/non-TTY
/// output. Each phase DTO is serialized in durable workflow order.
pub(crate) fn workbench_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let snapshot = workbench_presentation_snapshot(app);
    phase_workbench_lines(app, area, &snapshot.chrome, &snapshot.phase)
}

fn phase_workbench_lines(
    app: &ShellApp,
    area: Rect,
    chrome: &WorkbenchChromeModel,
    phase: &PhaseCockpitModel,
) -> Vec<Line<'static>> {
    let mut lines =
        workbench_header_lines(app, chrome, &phase.header, area.width as usize, usize::MAX);
    lines.push(blank());
    lines.extend(super::phase_pages::phase_cockpit_plain_lines(
        app,
        phase,
        area.width as usize,
    ));
    if let Some(question) = app.guided_scan_question_model() {
        lines.push(blank());
        lines.extend(super::guided_scan::guided_question_lines(
            &question,
            area.width as usize,
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_zoom_status_uses_the_visible_surface_name() {
        assert_eq!(
            phase_surface_zoom_label(PhaseSurfaceId::ProveStatus),
            "STATUS / NEXT"
        );
        assert_eq!(
            phase_surface_zoom_label(PhaseSurfaceId::ProveLadder),
            "PROOF LADDER"
        );
        assert_eq!(phase_surface_zoom_label(PhaseSurfaceId::MapDfd), "DFD");
    }
}
