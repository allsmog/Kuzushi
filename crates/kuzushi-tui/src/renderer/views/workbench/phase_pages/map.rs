use super::*;
use crate::ui_view_models::{
    project_context_columns, AttackSurfaceRiskModel, DfdFlowModel, DfdModel, EngagementHeaderModel,
    MapPhaseModel, ModuleRisk, NextScansState, ProjectContextCell, ProjectContextRow,
    ProjectModelOrigin, WorklistRowModel,
};
use ratatui::layout::{Constraint, Direction, Layout};

const GRID_MIN_WIDTH: u16 = 78;
const COMPACT_MIN_HEIGHT: u16 = 14;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &MapPhaseModel,
    _header: &EngagementHeaderModel,
    state: PhaseRenderState,
) {
    if state.surface == Some(PhaseSurfaceId::MapReadiness) && model.recorded_context_issue.is_some()
    {
        return render_map_action_card(frame, area, model, state);
    }
    if render_selected_map_surface(frame, area, app, model, state) {
        return;
    }
    render_map_grid(frame, area, model, state);
}

fn render_selected_map_surface(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) -> bool {
    match state.role {
        crate::ui_view_models::SurfaceRole::Canvas => {
            render_map_canvas(frame, area, app, model, state);
            return true;
        }
        crate::ui_view_models::SurfaceRole::Drawer => {
            render_map_action_card(frame, area, model, state);
            return true;
        }
        crate::ui_view_models::SurfaceRole::Standard => {}
    }
    if let Some(pane) = state.surface {
        render_map_pane(frame, area, model, state, pane);
        return true;
    }
    false
}

fn render_map_grid(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    if area.width < GRID_MIN_WIDTH || area.height < COMPACT_MIN_HEIGHT {
        render_compact(frame, area, model, state);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);
    let top = split_row(rows[0], 54);
    let bottom = split_row(rows[1], 54);
    render_context(frame, top[0], model, state);
    render_attack_surface(frame, top[1], model, state);
    render_hot_modules(frame, bottom[0], model, state);
    render_dfd_readiness(frame, bottom[1], model, state);
}

pub(super) fn plain_lines(
    app: &ShellApp,
    model: &MapPhaseModel,
    _header: &EngagementHeaderModel,
    width: usize,
) -> Vec<Line<'static>> {
    if let Some(issue) = model.recorded_context_issue.as_deref() {
        return recorded_context_issue_lines(issue, width);
    }
    if crate::ui_view_models::map_gallery_is_primary(app) {
        let mut lines = crate::renderer::views::scene::map_summary_plain_lines(app, width);
        lines.push(map_artifact_status_line(model, width));
        return lines;
    }
    map_evidence_plain_lines(model, width)
}

fn map_evidence_plain_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = divider_lines(
        "PROJECT CONTEXT",
        context_lines(model, width, STACKED_CONTEXT_ROWS),
        width,
    );
    lines.extend(divider_lines(
        "ATTACK SURFACE",
        attack_surface_lines(model.attack_surface.as_ref(), width),
        width,
    ));
    lines.extend(divider_lines(
        "HOT MODULES",
        hot_modules_pane_lines(model, width),
        width,
    ));
    lines.extend(divider_lines(
        "WORKLIST",
        worklist_pane_lines(model, width),
        width,
    ));
    lines.extend(divider_lines(
        "THREAT MODEL / DFD",
        dfd_readiness_lines(&model.dfd, width),
        width,
    ));
    lines
}

fn split_row(area: Rect, left_percent: u16) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(left_percent),
            Constraint::Percentage(100 - left_percent),
        ])
        .split(area)
}

fn render_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let mut lines = context_lines(model, width, STACKED_CONTEXT_ROWS);
    lines.push(divider("ATTACK SURFACE", area.width.saturating_sub(2)));
    lines.extend(attack_surface_lines(model.attack_surface.as_ref(), width));
    lines.push(divider("HOT MODULES", area.width.saturating_sub(2)));
    lines.extend(hot_modules_pane_lines(model, width));
    lines.push(divider("WORKLIST", area.width.saturating_sub(2)));
    lines.extend(worklist_pane_lines(model, width));
    lines.push(divider("THREAT MODEL / DFD", area.width.saturating_sub(2)));
    lines.extend(dfd_readiness_lines(&model.dfd, width));
    render_lines_pane(
        frame,
        area,
        "MAP · Tab focus · z visualize",
        lines,
        state.focus.unwrap_or(PhaseSurfaceId::MapReadiness),
        state,
    );
}

/// The dominant Map workspace: the repository/data-flow picture with attack
/// surface and hot-module annotations folded in, replacing the four-pane grid.
fn render_map_canvas(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    let sections = crate::renderer::views::scene::map_canvas_sections(area);
    crate::renderer::views::scene::render_embedded_map_gallery(
        frame,
        sections[0],
        app,
        state.scroll(PhaseSurfaceId::MapDfd),
    );
    frame.render_widget(
        Paragraph::new(map_artifact_status_line(model, sections[1].width as usize)),
        sections[1],
    );
}

fn map_artifact_status_line(model: &MapPhaseModel, width: usize) -> Line<'static> {
    let files = model
        .context
        .details
        .as_ref()
        .map(|details| details.files.as_str())
        .unwrap_or("file inventory unavailable");
    let status = format!(
        "{} · {} · {} · repo index:{} · {} · {} nodes · {} flows",
        model.threat_model_freshness.verdict,
        model.project.scope_label,
        model.project.revision_label,
        model.context.state,
        files,
        model.dfd.nodes.len(),
        model.dfd.flows.len(),
    );
    Line::styled(fit(&status, width), theme::muted())
}

/// The contextual action drawer: missing artifacts become inline actions
/// instead of status text. The threat model is refined when one exists and
/// bootstrapped when none does; either way it seeds scan recommendations and
/// trust-boundary scope.
fn render_map_action_card(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let (title, lines) = map_action_card_lines(model, width);
    render_lines_pane(
        frame,
        area,
        title,
        lines,
        PhaseSurfaceId::MapReadiness,
        state,
    );
}

fn map_action_card_lines(
    model: &MapPhaseModel,
    width: usize,
) -> (&'static str, Vec<Line<'static>>) {
    if let Some(issue) = model.recorded_context_issue.as_deref() {
        return ("MAP CONTEXT", recorded_context_issue_lines(issue, width));
    }
    if let Some(hint) = model.scope_suggestion.as_deref() {
        return ("NEXT ACTION", scope_suggestion_lines(hint, width));
    }
    map_evidence_action(model, width).unwrap_or_else(|| ready_map_lines(model, width))
}

fn recorded_context_issue_lines(issue: &str, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit("▸ Enter inspect Map runs", width),
        theme::accent(),
    )];
    lines.extend(
        wrap_text(issue, width)
            .into_iter()
            .map(|line| Line::styled(line, theme::warn())),
    );
    lines.push(Line::styled(
        fit("Type plan map to prepare new context", width),
        theme::muted(),
    ));
    lines
}

fn map_evidence_action(
    model: &MapPhaseModel,
    width: usize,
) -> Option<(&'static str, Vec<Line<'static>>)> {
    if model.dfd.empty_hint.is_some() || model.empty_hint.is_some() {
        return Some(("NEXT ACTION", missing_threat_model_lines(model, width)));
    }
    if model.threat_model_freshness.requires_attention {
        return Some(("NEXT ACTION", stale_threat_model_lines(model, width)));
    }
    if model.context.state.eq_ignore_ascii_case("stale") {
        return Some(("NEXT ACTION", stale_context_lines(model, width)));
    }
    None
}

fn ready_map_lines(model: &MapPhaseModel, width: usize) -> (&'static str, Vec<Line<'static>>) {
    let mut lines = vec![Line::styled(
        fit(&context_status_line(model), width),
        artifact_state_style(model.context.state),
    )];
    lines.extend(next_scan_lines(&model.next_scans, width));
    ("PROJECT CONTEXT · NEXT SCANS", lines)
}

fn missing_threat_model_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(fit("⚠ No threat model detected", width), theme::warn()),
        Line::styled(
            fit(
                "generating one seeds scan recommendations and trust-boundary scope",
                width,
            ),
            theme::muted(),
        ),
        Line::styled(
            fit("  [x] repository context and data flows", width),
            theme::primary(),
        ),
        Line::styled(
            fit("  [ ] existing threat model · [ ] external intel", width),
            theme::muted(),
        ),
        Line::from(vec![
            Span::styled("▸ Enter generate threat model", theme::accent()),
            Span::styled("   Tab focus map · not now", theme::muted()),
        ]),
    ];
    if let Some(hint) = model.empty_hint.as_deref() {
        lines.insert(1, Line::styled(fit(hint, width), theme::muted()));
    }
    lines
}

fn stale_threat_model_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    if model.threat_model_freshness.verdict == "manual edit" {
        return divergent_mirror_lines(model, width);
    }
    vec![
        Line::styled(
            fit(
                &format!(
                    "⚠ threat model {} — verify or refine recommended",
                    model.threat_model_freshness.verdict
                ),
                width,
            ),
            theme::warn(),
        ),
        Line::styled(
            fit(&context_status_line(model), width),
            artifact_state_style(model.context.state),
        ),
        Line::from(vec![
            Span::styled("▸ Enter refine threat model", theme::accent()),
            Span::styled("   keeps threat ids stable", theme::muted()),
        ]),
    ]
}

fn divergent_mirror_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled(
            fit("⚠ compatibility mirror has unadopted manual edits", width),
            theme::warn(),
        ),
        Line::styled(
            fit(&context_status_line(model), width),
            artifact_state_style(model.context.state),
        ),
        Line::styled(
            fit(
                "next: inspect diff · adopt edits · discard only with explicit force",
                width,
            ),
            theme::accent(),
        ),
    ]
}

fn stale_context_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled(
            fit("⚠ repository context stale — refresh recommended", width),
            theme::warn(),
        ),
        Line::styled(
            fit(
                &format!(
                    "threat-model verdict remains {} until its own verification changes",
                    model.threat_model_freshness.verdict
                ),
                width,
            ),
            theme::muted(),
        ),
        Line::from(vec![
            Span::styled("▸ Enter refresh context", theme::accent()),
            Span::styled("   threat model is not relabeled", theme::muted()),
        ]),
    ]
}

/// Repository size can motivate a scope proposal without requiring a split.
fn scope_suggestion_lines(hint: &str, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled(fit("Optional: repository scopes", width), theme::warn()),
        Line::styled(fit(hint, width), theme::muted()),
        Line::styled(fit("▸ Enter review scope proposal", width), theme::accent()),
        Line::styled(
            fit("Type next for whole-repository Map", width),
            theme::muted(),
        ),
        Line::styled(fit("Tab focus map", width), theme::muted()),
    ]
}

fn render_map_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
    surface: PhaseSurfaceId,
) {
    match surface {
        PhaseSurfaceId::MapReadiness => render_context(frame, area, model, state),
        PhaseSurfaceId::MapAttackSurface => render_attack_surface(frame, area, model, state),
        PhaseSurfaceId::MapHotModules => render_hot_modules(frame, area, model, state),
        PhaseSurfaceId::MapDfd => render_dfd_readiness(frame, area, model, state),
        _ => render_context(frame, area, model, state),
    }
}

fn render_context(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "PROJECT CONTEXT",
        context_lines(
            model,
            area.width.saturating_sub(2) as usize,
            area.height.saturating_sub(1),
        ),
        PhaseSurfaceId::MapReadiness,
        state,
    );
}

/// Stacked Map projections continue with further sections below the receipt,
/// so they grant it no spare rows: one line per receipt row.
const STACKED_CONTEXT_ROWS: u16 = 0;

fn context_lines(model: &MapPhaseModel, width: usize, rows: u16) -> Vec<Line<'static>> {
    let mut lines = vec![context_heading_line(
        &model.project.scope_label,
        &model.project.revision_label,
        width,
    )];
    if let Some(hint) = model.empty_hint.as_deref() {
        lines.push(Line::styled(fit(hint, width), theme::warn()));
    }
    lines.push(Line::styled(
        fit(&context_status_line(model), width),
        artifact_state_style(model.context.state),
    ));
    let wrap = crate::ui_view_models::map_context_fit(model, width, rows).wrap_summaries;
    let table = project_context_columns(&model.project, width);
    for row in &table.rows {
        if wrap {
            lines.extend(
                row.wrapped_segments()
                    .into_iter()
                    .map(|segments| context_segments_line_for(row.origin, segments)),
            );
        } else {
            lines.push(context_row_line(row));
        }
    }
    lines
}

/// One receipt row, styled from the shared column projection so the pane and
/// plain output cannot disagree about which cells a row has.
fn context_row_line(row: &ProjectContextRow) -> Line<'static> {
    context_segments_line_for(row.origin, row.segments())
}

fn context_segments_line_for(
    origin: ProjectModelOrigin,
    segments: Vec<crate::ui_view_models::ProjectContextSegment>,
) -> Line<'static> {
    Line::from(
        segments
            .into_iter()
            .map(|segment| Span::styled(segment.text, context_cell_style(segment.cell, origin)))
            .collect::<Vec<_>>(),
    )
}

fn context_cell_style(
    cell: ProjectContextCell,
    origin: ProjectModelOrigin,
) -> ratatui::style::Style {
    match cell {
        ProjectContextCell::Origin | ProjectContextCell::Section | ProjectContextCell::State => {
            origin_style(origin)
        }
        ProjectContextCell::Action => theme::accent(),
        ProjectContextCell::Rule | ProjectContextCell::Summary => theme::muted(),
    }
}

fn context_heading_line(scope: &str, revision: &str, width: usize) -> Line<'static> {
    let separator = " · ";
    let combined_width = display_width(scope) + display_width(separator) + display_width(revision);
    if combined_width <= width {
        return Line::from(vec![
            Span::styled(scope.to_string(), theme::heading()),
            Span::styled(format!("{separator}{revision}"), theme::muted()),
        ]);
    }
    if width < 16 {
        return Line::styled(fit(scope, width), theme::heading());
    }
    let content_width = width.saturating_sub(display_width(separator));
    let revision_width = content_width / 3;
    let scope_width = content_width.saturating_sub(revision_width);
    let scope = fit(scope, scope_width);
    let revision = fit(revision, revision_width);
    Line::from(vec![
        Span::styled(scope, theme::heading()),
        Span::styled(format!("{separator}{revision}"), theme::muted()),
    ])
}

/// Keep the repository-index status distinct from the accepted Map context.
fn context_status_line(model: &MapPhaseModel) -> String {
    let state = model.context.state.to_string();
    let status = model
        .context
        .status
        .strip_prefix(&format!("{state}. "))
        .unwrap_or(&model.context.status);
    format!("repo index:{state} · {status}")
}

fn render_attack_surface(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "ATTACK SURFACE · z terrain",
        attack_surface_lines(
            model.attack_surface.as_ref(),
            area.width.saturating_sub(2) as usize,
        ),
        PhaseSurfaceId::MapAttackSurface,
        state,
    );
}

fn attack_surface_lines(
    attack_surface: Option<&AttackSurfaceRiskModel>,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(model) = attack_surface else {
        return empty_state_panel(
            "no attack-surface artifact",
            &["run `next` to inventory externally reachable surfaces"],
            &[("next", "continue workspace phase")],
        );
    };
    let mut lines = vec![Line::styled(fit(&model.summary, width), theme::primary())];
    lines.extend(model.hot_surfaces.iter().map(|row| {
        let score = (row.score > 0)
            .then(|| format!(" · {}", row.score))
            .unwrap_or_default();
        Line::from(vec![
            Span::styled(format!("{:<8}", row.tier), tier_style(&row.tier)),
            Span::styled(
                fit(
                    &format!("{} · {}{score}", row.framework, row.title),
                    width.saturating_sub(9),
                ),
                theme::muted(),
            ),
        ])
    }));
    lines.push(Line::styled(
        "▸ z open terrain visualization",
        theme::accent(),
    ));
    lines
}

fn render_hot_modules(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let mut lines = hot_modules_pane_lines(model, width);
    lines.push(divider("WORKLIST", area.width.saturating_sub(2)));
    lines.extend(worklist_pane_lines(model, width));
    render_lines_pane(
        frame,
        area,
        "HOT MODULES · z heatmap",
        lines,
        PhaseSurfaceId::MapHotModules,
        state,
    );
}

/// Hot-module risk rows followed by coverage-ledger NEXT SCANS rows; one
/// builder keeps the grid pane, compact stack, and plain output identical.
fn hot_modules_pane_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = hot_module_lines(&model.hot_modules.modules, width);
    lines.extend(next_scan_lines(&model.next_scans, width));
    lines
}

fn next_scan_lines(next_scans: &NextScansState, width: usize) -> Vec<Line<'static>> {
    let rows = match next_scans {
        NextScansState::Pending => return Vec::new(),
        NextScansState::Unavailable(error) => {
            return vec![
                Line::styled("NEXT SCANS", theme::heading()),
                Line::styled(fit(&format!("unavailable: {error}"), width), theme::muted()),
            ];
        }
        NextScansState::Ready(rows) => rows,
    };
    let mut lines = vec![Line::styled("NEXT SCANS", theme::heading())];
    if rows.is_empty() {
        lines.push(Line::styled(
            fit("coverage current — nothing recommended", width),
            theme::muted(),
        ));
        return lines;
    }
    lines.extend(rows.iter().map(|row| {
        let label = format!("{} · {} · {}", row.scope, row.phase, row.reason);
        Line::from(vec![
            Span::styled(fit(&label, width.min(34)), theme::primary()),
            Span::styled(
                fit(&format!("  {}", row.evidence), width.saturating_sub(36)),
                theme::muted(),
            ),
        ])
    }));
    lines
}

fn hot_module_lines(modules: &[ModuleRisk], width: usize) -> Vec<Line<'static>> {
    if modules.is_empty() {
        return vec![Line::styled(
            fit("no finding-bearing modules yet — run `scan`", width),
            theme::muted(),
        )];
    }
    modules
        .iter()
        .take(8)
        .flat_map(|module| hot_module_row_lines(module, width))
        .collect()
}

fn hot_module_row_lines(module: &ModuleRisk, width: usize) -> Vec<Line<'static>> {
    let metadata = hot_module_metadata(module);
    if display_width(&module.module) + 2 + display_width(&metadata) <= width {
        return vec![Line::from(vec![
            Span::styled(module.module.clone(), theme::primary()),
            Span::styled(format!("  {metadata}"), theme::muted()),
        ])];
    }
    let module_line = Line::styled(fit(&module.module, width), theme::primary());
    let metadata_lines = wrap_text(&metadata, width)
        .into_iter()
        .map(|line| Line::styled(line, theme::muted()));
    std::iter::once(module_line).chain(metadata_lines).collect()
}

fn hot_module_metadata(module: &ModuleRisk) -> String {
    let [critical, high, medium, low, info] = module.counts;
    format!(
        "{:>4.1} · {critical}C {high}H {medium}M {low}L {info}I",
        module.score
    )
}

/// Top-5 risk-ranked files with a degraded chip and a "run the full worklist"
/// affordance. Shared by the grid pane, the compact stack, the canvas, and
/// plain output so every Map surface shows the same worklist summary.
const WORKLIST_PANE_ROWS: usize = 5;

fn worklist_pane_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    let worklist = &model.worklist;
    if worklist.rows.is_empty() {
        return empty_worklist_pane_lines(model, width);
    }
    let mut lines = Vec::new();
    for reason in &worklist.degraded {
        lines.push(Line::styled(
            fit(&format!("⚠ degraded — {reason}"), width),
            theme::warn(),
        ));
    }
    lines.extend(
        worklist
            .rows
            .iter()
            .take(WORKLIST_PANE_ROWS)
            .map(|row| worklist_row_line(row, width)),
    );
    // Report the true ranked population, not the capped row list.
    if worklist.ranked_total > WORKLIST_PANE_ROWS {
        lines.push(Line::styled(
            fit(
                &format!("run `worklist` for all {}", worklist.ranked_total),
                width,
            ),
            theme::muted(),
        ));
    }
    lines
}

/// Honest empty-worklist copy: never claim "run context:build" while the
/// snapshot is mid-build, and never claim it when the surface map is present
/// but simply carried no threshold-crossing file.
fn empty_worklist_pane_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
    let worklist = &model.worklist;
    // (b) The context snapshot is still building; asserting "run context:build"
    // over an artifact that is mid-hydration would be a lie.
    if model.context.running.is_some() {
        return vec![Line::styled(fit("ranking files…", width), theme::muted())];
    }
    // No artifact at all: the build → rank call-to-action is honest here.
    if let Some(hint) = worklist.empty_hint.as_deref() {
        return vec![Line::styled(fit(hint, width), theme::muted())];
    }
    // (a) The surface map is present but no file crossed the signal threshold;
    // "run context:build" would be wrong — it already ran.
    let below = (worklist.unranked_count > 0)
        .then(|| format!(" · {} files below threshold", worklist.unranked_count))
        .unwrap_or_default();
    vec![Line::styled(
        fit(
            &format!("no file crossed the signal threshold{below}"),
            width,
        ),
        theme::muted(),
    )]
}

fn worklist_row_line(row: &WorklistRowModel, width: usize) -> Line<'static> {
    let label = format!("#{} {}", row.rank, row.location);
    Line::from(vec![
        Span::styled(fit(&label, width.min(30)), theme::primary()),
        Span::styled(
            fit(
                &format!("  {} {}", row.glyphs, row.summary),
                width.saturating_sub(32),
            ),
            theme::muted(),
        ),
    ])
}

fn render_dfd_readiness(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        "THREAT MODEL / DFD · z open",
        dfd_readiness_lines(&model.dfd, area.width.saturating_sub(2) as usize),
        PhaseSurfaceId::MapDfd,
        state,
    );
}

fn dfd_readiness_lines(dfd: &DfdModel, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = dfd.empty_hint.as_deref() {
        return missing_dfd_lines(hint);
    }
    ready_dfd_lines(dfd, width)
}

fn missing_dfd_lines(hint: &str) -> Vec<Line<'static>> {
    empty_state_panel(
        "DFD not ready",
        &[hint],
        &[("run threat-model:build {}", "build threat model")],
    )
}

fn ready_dfd_lines(dfd: &DfdModel, width: usize) -> Vec<Line<'static>> {
    let crossing = dfd.flows.iter().filter(|flow| flow.crosses).count();
    let summary = format!(
        "ready · {} nodes · {} flows · {crossing} trust crossings",
        dfd.nodes.len(),
        dfd.flows.len()
    );
    let mut lines = vec![Line::styled(fit(&summary, width), theme::success())];
    lines.push(Line::styled(
        fit(&format!("zones: {}", dfd.zones.join(" → ")), width),
        theme::muted(),
    ));
    lines.extend(
        dfd.flows
            .iter()
            .take(6)
            .map(|flow| dfd_flow_line(flow, width)),
    );
    lines
}

fn dfd_flow_line(flow: &DfdFlowModel, width: usize) -> Line<'static> {
    let arrow = if flow.crosses { "⇒" } else { "→" };
    let label = format!("{} {arrow} {} · {}", flow.from, flow.to, flow.label);
    let style = if flow.crosses {
        theme::warn()
    } else {
        theme::primary()
    };
    Line::styled(fit(&label, width), style)
}

fn origin_style(origin: ProjectModelOrigin) -> ratatui::style::Style {
    match origin {
        ProjectModelOrigin::Local | ProjectModelOrigin::Inherited => theme::success(),
        ProjectModelOrigin::Missing => theme::muted(),
        ProjectModelOrigin::Stale => theme::warn(),
    }
}

fn artifact_state_style(state: &str) -> ratatui::style::Style {
    match state {
        "present" => theme::success(),
        "malformed" => theme::danger(),
        _ => theme::muted(),
    }
}

fn tier_style(tier: &str) -> ratatui::style::Style {
    match tier.to_ascii_lowercase().as_str() {
        "critical" | "high" => theme::danger(),
        "medium" => theme::warn(),
        _ => theme::muted(),
    }
}

#[cfg(test)]
mod next_scan_tests {
    use super::*;
    use crate::ui_view_models::NextScanRow;

    fn line_width(line: &Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum()
    }

    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn pending_recommendations_draw_no_chrome() {
        assert!(next_scan_lines(&NextScansState::Pending, 80).is_empty());
    }

    #[test]
    fn scope_suggestion_card_discloses_whole_repository_choice() {
        let app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            &app,
            kuzushi_core::WorkflowPhase::Map,
        );
        let crate::ui_view_models::PhaseCockpitBody::Map(mut map) = model.body else {
            panic!("map body expected");
        };
        assert!(
            map.dfd.empty_hint.is_some() || map.empty_hint.is_some(),
            "fixture must be in the missing-threat-model state"
        );
        map.scope_suggestion = Some("81259 files indexed — optional scopes".to_string());

        for width in [38, 58, 78, 94, 118, 158] {
            let (title, lines) = map_action_card_lines(&map, width);
            assert_eq!(title, "NEXT ACTION");
            let rendered = text(&lines);
            assert!(
                rendered.contains("review scope proposal"),
                "{width}: {rendered}"
            );
            assert!(
                rendered.contains("81259 files indexed"),
                "{width}: {rendered}"
            );
            assert!(rendered.contains("Optional:"), "{width}: {rendered}");
            assert!(
                rendered.contains("Type next for whole-repository Map"),
                "{width}: {rendered}"
            );
            assert!(!rendered.contains("generate threat model"), "{rendered}");
            assert!(lines.iter().all(|line| line.width() <= width));
        }
    }

    #[test]
    fn ready_rows_and_failures_render_under_a_next_scans_heading() {
        let ready = NextScansState::Ready(vec![NextScanRow {
            scope: "root".to_string(),
            phase: "scan".to_string(),
            reason: "changed".to_string(),
            evidence: "14 files changed since a1b2c3d4".to_string(),
        }]);
        let rendered = text(&next_scan_lines(&ready, 80));
        assert!(rendered.contains("NEXT SCANS"));
        assert!(rendered.contains("root \u{b7} scan \u{b7} changed"));
        assert!(rendered.contains("14 files changed"));

        let empty = text(&next_scan_lines(&NextScansState::Ready(Vec::new()), 80));
        assert!(empty.contains("coverage current"));

        let failed = text(&next_scan_lines(
            &NextScansState::Unavailable("ledger locked".to_string()),
            80,
        ));
        assert!(failed.contains("unavailable: ledger locked"));
    }

    #[test]
    fn context_heading_budgets_scope_and_revision_as_one_line() {
        let line = context_heading_line("日本語の長いスコープ", "revision-with-a-long-name", 20);
        let rendered = line.to_string();

        assert!(line_width(&line) <= 20);
        assert!(
            rendered.starts_with("日本語"),
            "scope identity was lost: {rendered}"
        );
        assert!(
            display_width(line.spans[1].content.as_ref()) > display_width(" · "),
            "revision was lost: {rendered}"
        );

        let roomy = context_heading_line("scope:auth", "rev:a1b2c3", 40).to_string();
        assert!(roomy.contains("scope:auth"));
        assert!(roomy.contains("rev:a1b2c3"));

        let long = context_heading_line(
            "scope:services/identity/authorization",
            "rev:feature/long-lived-security-branch",
            96,
        )
        .to_string();
        assert!(long.contains("scope:services/identity/authorization"));
        assert!(long.contains("rev:feature/long-lived-security-branch"));
    }

    #[test]
    fn stale_context_does_not_relabel_a_verified_threat_model() {
        let mut map = map_fixture();
        map.context.state = "stale";
        map.threat_model_freshness = crate::ui_view_models::ThreatModelFreshnessModel {
            verdict: "verified".to_string(),
            document_sha256: Some("sha256:model".to_string()),
            current_sha256: Some("sha256:model".to_string()),
            requires_attention: false,
        };

        let rendered = text(&stale_context_lines(&map, 100));

        assert!(rendered.contains("repository context stale"), "{rendered}");
        assert!(rendered.contains("verdict remains verified"), "{rendered}");
        assert!(!rendered.contains("threat model stale"), "{rendered}");
    }

    #[test]
    fn threat_model_action_uses_the_document_verdict() {
        let mut map = map_fixture();
        map.context.state = "present";
        map.threat_model_freshness = crate::ui_view_models::ThreatModelFreshnessModel {
            verdict: "failed".to_string(),
            document_sha256: Some("sha256:model".to_string()),
            current_sha256: Some("sha256:model".to_string()),
            requires_attention: true,
        };

        let rendered = text(&stale_threat_model_lines(&map, 100));

        assert!(rendered.contains("threat model failed"), "{rendered}");
        assert!(!rendered.contains("context stale"), "{rendered}");
    }

    #[test]
    fn manual_mirror_edit_offers_only_explicit_reconciliation_actions() {
        let mut map = map_fixture();
        map.threat_model_freshness = crate::ui_view_models::ThreatModelFreshnessModel {
            verdict: "manual edit".to_string(),
            document_sha256: Some("sha256:active".to_string()),
            current_sha256: Some("sha256:edited".to_string()),
            requires_attention: true,
        };

        let rendered = text(&stale_threat_model_lines(&map, 100));

        assert!(rendered.contains("unadopted manual edits"), "{rendered}");
        assert!(rendered.contains("inspect diff"), "{rendered}");
        assert!(rendered.contains("adopt edits"), "{rendered}");
        assert!(rendered.contains("explicit force"), "{rendered}");
        assert!(!rendered.contains("refine"), "{rendered}");
    }

    fn map_fixture() -> MapPhaseModel {
        let app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            &app,
            kuzushi_core::WorkflowPhase::Map,
        );
        match model.body {
            crate::ui_view_models::PhaseCockpitBody::Map(map) => map,
            _ => panic!("map body expected"),
        }
    }

    #[test]
    fn narrow_context_rows_separate_a_full_width_section_from_its_summary() {
        let map = map_fixture();
        assert!(
            map.project
                .rows
                .iter()
                .any(|row| row.section == "review surface"),
            "fixture must carry the widest section label"
        );

        let rendered = text(&context_lines(&map, 60, STACKED_CONTEXT_ROWS));

        assert!(rendered.contains("review surface 0 items"), "{rendered}");
    }

    /// #172: a card wide enough to afford them spends its columns on the
    /// state and next action the project model already carries, instead of
    /// leaving the pane's right half empty.
    #[test]
    fn wide_context_rows_carry_the_state_and_next_action() {
        let map = map_fixture();

        let rendered = text(&context_lines(&map, 100, STACKED_CONTEXT_ROWS));

        assert!(rendered.contains("review surface"), "{rendered}");
        assert!(
            rendered.contains("\u{2502} missing"),
            "state cell: {rendered}"
        );
        assert!(
            rendered.contains("\u{25b8} findings"),
            "action cell: {rendered}"
        );
    }

    #[test]
    fn empty_worklist_while_context_builds_avoids_context_build_cta() {
        let mut map = map_fixture();
        map.worklist = crate::ui_view_models::WorklistViewModel::default();
        map.context.running = Some(crate::ui_view_models::ContextSnapshotRunning {
            tool: "context:build".to_string(),
            glyph: "⏵",
            message: "building snapshot",
        });

        let rendered = text(&worklist_pane_lines(&map, 100));

        assert!(rendered.contains("ranking files"), "{rendered}");
        assert!(
            !rendered.contains("context:build"),
            "must not claim context:build while it is mid-build: {rendered}"
        );
    }

    #[test]
    fn empty_worklist_with_surfaces_reports_threshold_not_context_build() {
        let mut map = map_fixture();
        map.context.running = None;
        map.worklist = crate::ui_view_models::WorklistViewModel {
            unranked_count: 3,
            ..Default::default()
        };

        let rendered = text(&worklist_pane_lines(&map, 100));

        assert!(
            rendered.contains("no file crossed the signal threshold"),
            "{rendered}"
        );
        assert!(rendered.contains("3 files below threshold"), "{rendered}");
        assert!(!rendered.contains("context:build"), "{rendered}");
    }

    #[test]
    fn worklist_pane_reports_true_ranked_population_not_capped_rows() {
        let mut map = map_fixture();
        map.worklist = crate::ui_view_models::WorklistViewModel {
            rows: (1..=6)
                .map(|rank| crate::ui_view_models::WorklistRowModel {
                    rank,
                    glyphs: "A".to_string(),
                    location: format!("src/f{rank}.rs"),
                    summary: "A 90/100".to_string(),
                })
                .collect(),
            ranked_total: 120,
            ..Default::default()
        };

        let rendered = text(&worklist_pane_lines(&map, 120));

        assert!(
            rendered.contains("run `worklist` for all 120"),
            "{rendered}"
        );
        assert!(!rendered.contains("for all 6"), "{rendered}");
    }

    #[test]
    fn hot_module_suffix_uses_its_actual_count_width() {
        let lines = hot_module_lines(
            &[ModuleRisk {
                module: "src/日本語/very-long-module-name".to_string(),
                counts: [10_000, 20_000, 30_000, 40_000, 50_000],
                score: 1000.0,
            }],
            40,
        );

        let rendered = text(&lines);
        assert!(lines.iter().all(|line| line_width(line) <= 40));
        for atom in [
            "src/日本語",
            "1000.0",
            "10000C",
            "20000H",
            "30000M",
            "40000L",
            "50000I",
        ] {
            assert!(rendered.contains(atom), "missing {atom:?}: {rendered}");
        }
    }
}

#[cfg(test)]
mod context_card_tests {
    use super::*;
    use crate::ui_view_models::{map_context_fit, ProjectModelOrigin, ProjectModelRow};

    fn map_model() -> crate::ui_view_models::MapPhaseModel {
        let app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            &app,
            kuzushi_core::WorkflowPhase::Map,
        );
        let crate::ui_view_models::PhaseCockpitBody::Map(map) = model.body else {
            panic!("map body expected");
        };
        map
    }

    fn receipt_rows(count: usize) -> Vec<ProjectModelRow> {
        (0..count)
            .map(|index| ProjectModelRow {
                section: "context feed",
                origin: ProjectModelOrigin::Local,
                state: "present",
                summary: format!("row {index}"),
                action: "context build",
            })
            .collect()
    }

    /// The layout sizes the status card from `map_context_fit`, so a
    /// disagreement with the lines this pane emits would either clip a receipt
    /// row or leave the blank rows the card exists to remove.
    #[test]
    fn card_height_matches_the_lines_the_pane_renders() {
        let mut model = map_model();
        for (rows, hint, budget) in [
            (0, None, 40),
            (3, None, 40),
            (12, Some("no context yet".to_string()), 40),
            (12, None, 6),
        ] {
            model.project.rows = receipt_rows(rows);
            model.empty_hint = hint;
            assert_eq!(
                context_lines(&model, 100, budget).len(),
                map_context_fit(&model, 100, budget).content_rows as usize,
                "{rows} receipt rows in {budget} spare rows"
            );
        }
    }

    /// No receipt row is ever dropped: the old eight-row cap hid everything
    /// past it without saying so.
    #[test]
    fn every_receipt_row_renders_even_past_the_old_limit() {
        let mut model = map_model();
        model.empty_hint = None;
        model.project.rows = receipt_rows(13);
        let text = text(&context_lines(&model, 100, 40));
        assert!(text.contains("row 12"), "{text}");
        assert_eq!(map_context_fit(&model, 100, 40).content_rows, 15);
    }

    /// With vertical room a long summary wraps under its own column instead of
    /// being cut off with an ellipsis; without room each row keeps one line.
    #[test]
    fn long_summaries_wrap_only_when_the_card_has_room() {
        let mut model = map_model();
        model.empty_hint = None;
        let mut rows = receipt_rows(1);
        rows[0].summary = "no persisted nested scopes yet; run next to decompose the \
                           repository into logical modules before threat modeling"
            .to_string();
        model.project.rows = rows;

        let roomy = text(&context_lines(&model, 90, 40));
        assert!(roomy.contains("threat modeling"), "{roomy}");
        assert!(!roomy.contains('…'), "{roomy}");

        let tight = context_lines(&model, 90, 3);
        assert_eq!(tight.len(), 3, "one line per row without room");
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
}
