use super::*;
use crate::ui_view_models::{
    AttackSurfaceRiskModel, DfdFlowModel, DfdModel, EngagementHeaderModel, MapPhaseModel,
    ModuleRisk, NextScansState, ProjectModelOrigin,
};
use ratatui::layout::{Constraint, Direction, Layout};

const GRID_MIN_WIDTH: u16 = 78;
const COMPACT_MIN_HEIGHT: u16 = 14;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    _header: &EngagementHeaderModel,
    state: PhaseRenderState,
) {
    if let Some(pane) = state.zoom {
        render_map_pane(frame, area, model, state, pane);
        return;
    }
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
    model: &MapPhaseModel,
    _header: &EngagementHeaderModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = divider_lines("PROJECT CONTEXT", context_lines(model, width), width);
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
    let mut lines = context_lines(model, width);
    lines.push(divider("ATTACK SURFACE", area.width.saturating_sub(2)));
    lines.extend(attack_surface_lines(model.attack_surface.as_ref(), width));
    lines.push(divider("HOT MODULES", area.width.saturating_sub(2)));
    lines.extend(hot_modules_pane_lines(model, width));
    lines.push(divider("THREAT MODEL / DFD", area.width.saturating_sub(2)));
    lines.extend(dfd_readiness_lines(&model.dfd, width));
    render_lines_pane(
        frame,
        area,
        "MAP · Tab focus · z visualize",
        lines,
        state.focus.unwrap_or(WorkbenchPane::Source),
        state,
    );
}

fn render_map_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    state: PhaseRenderState,
    pane: WorkbenchPane,
) {
    match pane {
        WorkbenchPane::Source => render_context(frame, area, model, state),
        WorkbenchPane::Center => render_attack_surface(frame, area, model, state),
        WorkbenchPane::Findings => render_hot_modules(frame, area, model, state),
        WorkbenchPane::Details => render_dfd_readiness(frame, area, model, state),
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
        context_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Source,
        state,
    );
}

fn context_lines(model: &MapPhaseModel, width: usize) -> Vec<Line<'static>> {
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
    lines.extend(model.project.rows.iter().take(8).map(|row| {
        Line::from(vec![
            Span::styled(
                format!("{} {:<14}", row.origin.glyph(), row.section),
                origin_style(row.origin),
            ),
            Span::styled(fit(&row.summary, width.saturating_sub(17)), theme::muted()),
        ])
    }));
    lines
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

/// "context:missing · missing. Next: …" repeats the state; strip a status
/// prefix that restates it so the line reads "context:missing · Next: …".
fn context_status_line(model: &MapPhaseModel) -> String {
    let state = model.context.state.to_string();
    let status = model
        .context
        .status
        .strip_prefix(&format!("{state}. "))
        .unwrap_or(&model.context.status);
    format!("context:{state} · {status}")
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
        WorkbenchPane::Center,
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
            &[("next", "continue Map")],
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
    render_lines_pane(
        frame,
        area,
        "HOT MODULES · z heatmap",
        hot_modules_pane_lines(model, area.width.saturating_sub(2) as usize),
        WorkbenchPane::Findings,
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
        WorkbenchPane::Details,
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
