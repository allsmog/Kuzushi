//! The security-viz gallery: a shared header plus page dispatch. The 3D
//! attack-surface page is drawn frame-level (see `render_scene_view`); every
//! other page is a 2D box-drawing diagram rendered here as styled lines.

use super::components::component_tree_rows;
use super::diagrams::{attack_path_lines, heatmap_lines};
use super::entry_points::entry_point_lines;
use super::line_page::{LinePageRows, PageDirection};
use super::worklist::worklist_rows;
use super::*;
use crate::scene3d::VizPage;
use crate::theme;
use crate::ui_view_models::{
    attack_tree, cached_findings_heatmap, component_stack, dfd_model, dfd_overview, display_target,
    entry_point_breakdown, taint_flow_path, worklist_model, AttackTree, DfdContextCounts, DfdKind,
    DfdModel, DfdOverview, DfdOverviewComponent, DfdOverviewZone,
};
use crate::ChainSeverity;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

/// The 3-row header shown above every gallery page: title, tagline, page nav.
/// Shared by the 3D frame renderer and the 2D line pages so they stay aligned.
pub(crate) fn gallery_header_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let page = app.router.scene().page();
    vec![
        responsive_header_line(
            &format!("◆ KUZUSHI VIZ · {}", page.label().to_uppercase()),
            &format!("◆ VIZ · {}", page.label().to_uppercase()),
            width,
            theme::heading(),
        ),
        responsive_header_line(
            page_tagline(page),
            compact_page_tagline(page),
            width,
            theme::muted(),
        ),
        responsive_nav_line("pages", &app.active_viz_pages(), page, width, "Tab cycles"),
    ]
}

pub(super) fn gallery_viewport_header_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if area.height >= 12 {
        return gallery_header_lines(app, area.width as usize);
    }
    let page = app.router.scene().page();
    let pages = app.active_viz_pages();
    let position = page_position_label(&pages, page);
    vec![Line::styled(
        fit_plain(
            &format!("◆ {}{position} · Tab", page.label().to_uppercase(),),
            area.width as usize,
        ),
        theme::heading(),
    )]
}

fn line_page_header_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = gallery_viewport_header_lines(app, area);
    if lines.len() > 1 {
        lines.push(Line::from(String::new()));
    }
    lines
}

/// Compact header for the visualization embedded directly in Map. The
/// Workbench already owns the screen title and journey chrome, so this keeps
/// only the selected projection's framing and its local tab rail.
pub(crate) fn map_gallery_header_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let page = app.current_map_viz_page();
    vec![
        responsive_header_line(
            &format!("◇ {} · {}", page.label().to_uppercase(), page_tagline(page)),
            &format!(
                "◇ {} · {}",
                page.label().to_uppercase(),
                compact_page_tagline(page)
            ),
            width,
            theme::heading(),
        ),
        responsive_nav_line(
            "views",
            &app.available_map_viz_pages(),
            page,
            width,
            "Tab cycles · z zoom",
        ),
    ]
}

/// Non-TTY projection of Map's default Summary tab. Plain output cannot
/// cycle tabs, so it expands the summary's executive description, zone-level
/// flow, and component tree in one exhaustive reading order.
pub(crate) fn map_summary_plain_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled("SYSTEM SUMMARY", theme::heading()),
        Line::styled(
            fit_plain("views · summary · dfd · z zoom", width),
            theme::muted(),
        ),
    ];
    lines.extend(summary_plain_lines(width, &dfd_model(app)));
    lines
}

/// Line-based entry for the gallery (2D pages always; the 3D page only in plain
/// / non-TTY mode, where the framebuffer can't run).
pub(crate) fn scene_page_lines(app: &ShellApp, area: Rect, page: VizPage) -> Vec<Line<'static>> {
    let mut lines = gallery_header_lines(app, area.width as usize);
    lines.push(Line::from(String::new()));
    lines.extend(page_body_lines(app, area, page));
    lines
}

/// The page's body as the rows it projects. The component tree and the
/// worklist wrap a value across display lines and group those lines per row;
/// every other line page fits each value to the canvas, so one of its display
/// lines is one row.
pub(super) fn page_body_rows(app: &ShellApp, area: Rect, page: VizPage) -> LinePageRows {
    let width = area.width as usize;
    match page {
        VizPage::Components => component_tree_rows(width, &component_stack(app)),
        VizPage::Worklist => worklist_rows(width, &worklist_model(app)),
        _ => LinePageRows::from_lines(page_body_lines(app, area, page)),
    }
}

/// Full-frame projection of a line page: the gallery header stays pinned and
/// the body is windowed by its rows, so the zoom states the same total Map's
/// embedded canvas does. `None` for a frame-rendered page, which has no row
/// model and keeps the generic pinned document viewport.
pub(crate) fn scene_line_page_viewport_lines(
    app: &ShellApp,
    area: Rect,
    scroll: usize,
) -> Option<Vec<Line<'static>>> {
    let page = app.router.scene().page();
    if page.is_frame_rendered() {
        return None;
    }
    let mut lines = line_page_header_lines(app, area);
    let body_height = scene_line_page_body_height(app, area);
    let rows = page_body_rows(app, area, page);
    match rows.window(body_height, scroll) {
        None => lines.extend(rows.into_lines().into_iter().take(body_height as usize)),
        Some(window) => {
            lines.push(Line::styled(window.position_label, theme::muted()));
            lines.extend(window.lines);
        }
    }
    // A canvas too short for the header itself keeps the generic viewport's
    // bound rather than overflowing it.
    lines.truncate(area.height as usize);
    Some(lines)
}

/// Page through display lines on the same body canvas the viewport draws.
/// `None` for a frame-rendered page.
pub(super) fn scene_line_page_step(
    app: &ShellApp,
    area: Rect,
    scroll: usize,
    direction: PageDirection,
) -> Option<usize> {
    let visible = scene_line_page_body_height(app, area);
    line_page_step(
        app,
        area,
        app.router.scene().page(),
        visible,
        scroll,
        direction,
    )
}

/// How far PgUp/PgDn move Map's embedded line page, whose whole body area is
/// the canvas its rows and position label share.
pub(super) fn embedded_line_page_step(
    app: &ShellApp,
    body: Rect,
    scroll: usize,
    direction: PageDirection,
) -> Option<usize> {
    let page = app.current_map_viz_page();
    line_page_step(app, body, page, body.height, scroll, direction)
}

fn line_page_step(
    app: &ShellApp,
    area: Rect,
    page: VizPage,
    visible: u16,
    scroll: usize,
    direction: PageDirection,
) -> Option<usize> {
    if page.is_frame_rendered() {
        return None;
    }
    Some(page_body_rows(app, area, page).page_step(visible, scroll, direction))
}

/// The display lines a full-frame line page leaves its rows (position label
/// included) below the pinned gallery header and its blank separator.
pub(super) fn scene_line_page_body_height(app: &ShellApp, area: Rect) -> u16 {
    let pinned = line_page_header_lines(app, area).len();
    area.height.saturating_sub(pinned as u16)
}

pub(super) fn page_body_lines(app: &ShellApp, area: Rect, page: VizPage) -> Vec<Line<'static>> {
    let width = area.width as usize;
    match page {
        VizPage::AttackPath => attack_path_lines(width, &taint_flow_path(app)),
        VizPage::EntryPoints => entry_point_lines(width, &entry_point_breakdown(app)),
        VizPage::Components => component_tree_rows(width, &component_stack(app)).into_lines(),
        VizPage::Heatmap => heatmap_lines(width, &cached_findings_heatmap(app)),
        VizPage::Worklist => worklist_rows(width, &worklist_model(app)).into_lines(),
        // Frame-rendered pages (3D terrain + box-drawing graph/tree) can't draw
        // in the line/plain path; show a short note instead.
        VizPage::AttackSurface => attack_surface_plain_lines(app, width),
        VizPage::Summary => summary_plain_lines(width, &dfd_model(app)),
        VizPage::Dfd => dfd_plain_lines(width, &dfd_model(app)),
        VizPage::ExploitChain => exploit_chain_plain_lines(width, &attack_tree(app)),
    }
}

fn exploit_chain_plain_lines(width: usize, model: &AttackTree) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return crate::renderer::empty_state_panel(
            "no exploit chain",
            &[hint],
            &[("exploit-chain:scan", "build entry-to-impact chains")],
        );
    }
    let mut lines = vec![Line::from(vec![Span::styled(
        attack_tree_count_label(model),
        theme::accent(),
    )])];
    for (index, chain) in model.chains.iter().enumerate() {
        append_exploit_chain_lines(
            &mut lines,
            width,
            index,
            &chain.title,
            chain.severity,
            chain.impact_description.as_deref(),
            chain.narrative.as_deref(),
            &chain.preconditions,
            &chain.steps,
            chain.hidden_step_count,
        );
    }
    if model.hidden_chain_count > 0 {
        lines.push(Line::styled(
            format!("  +{} more chains", model.hidden_chain_count),
            theme::muted(),
        ));
    }
    lines
}

fn attack_tree_count_label(model: &AttackTree) -> String {
    let total = model.chains.len() + model.hidden_chain_count;
    if model.hidden_chain_count == 0 {
        format!("ATTACK TREE · {total} chains")
    } else {
        format!(
            "ATTACK TREE · {total} chains · showing {}",
            model.chains.len()
        )
    }
}

fn append_exploit_chain_lines(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    index: usize,
    title: &str,
    severity: ChainSeverity,
    impact: Option<&str>,
    narrative: Option<&str>,
    preconditions: &[String],
    steps: &[String],
    hidden_step_count: usize,
) {
    lines.push(chain_header_line(width, index, title, severity));
    append_optional_chain_line(lines, width, "impact", impact);
    append_optional_chain_line(lines, width, "narrative", narrative);
    append_precondition_lines(lines, width, preconditions);
    append_step_lines(lines, width, steps, hidden_step_count);
}

fn chain_header_line(
    width: usize,
    index: usize,
    title: &str,
    severity: ChainSeverity,
) -> Line<'static> {
    plain_line(
        width,
        format!(
            "  {}. [{}] {}",
            index + 1,
            chain_severity_label(severity),
            title
        ),
    )
}

fn append_precondition_lines(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    preconditions: &[String],
) {
    for precondition in preconditions.iter().take(3) {
        lines.push(plain_line(
            width,
            format!("      precondition: {precondition}"),
        ));
    }
}

fn append_step_lines(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    steps: &[String],
    hidden_step_count: usize,
) {
    for (step_index, step) in steps.iter().enumerate() {
        lines.push(plain_line(
            width,
            format!("      {}. {}", step_index + 1, step),
        ));
    }
    if hidden_step_count > 0 {
        lines.push(plain_line(
            width,
            format!("      +{hidden_step_count} more steps"),
        ));
    }
}

fn append_optional_chain_line(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    label: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        lines.push(plain_line(width, format!("      {label}: {value}")));
    }
}

fn plain_line(width: usize, text: String) -> Line<'static> {
    Line::from(vec![Span::raw(fit_plain(&text, width))])
}

fn chain_severity_label(severity: ChainSeverity) -> &'static str {
    match severity {
        ChainSeverity::Critical => "critical",
        ChainSeverity::High => "high",
        ChainSeverity::Medium => "medium",
    }
}

fn dfd_plain_lines(width: usize, model: &DfdModel) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return crate::renderer::empty_state_panel(
            "no data-flow diagram",
            &[hint],
            &[("threat-model:build", "map trust zones and flows")],
        );
    }
    let crossings = model.flows.iter().filter(|flow| flow.crosses).count();
    let mut lines = vec![Line::from(vec![Span::styled(
        format!(
            "DFD · {} nodes · {} flows · {} zones · {crossings} boundary crossings",
            model.nodes.len(),
            model.flows.len(),
            model.zones.len()
        ),
        theme::accent(),
    )])];
    append_dfd_notice(&mut lines, width, model);
    append_dfd_node_lines(&mut lines, width, model);
    append_dfd_flow_lines(&mut lines, width, model);
    lines
}

fn append_dfd_node_lines(lines: &mut Vec<Line<'static>>, width: usize, model: &DfdModel) {
    lines.push(Line::from(vec![Span::styled("NODES", theme::heading())]));
    for zone in &model.zones {
        lines.push(Line::from(vec![Span::styled(
            fit_plain(&format!("  [{zone}]"), width),
            theme::muted(),
        )]));
        for node in model.nodes.iter().filter(|node| &node.zone == zone) {
            append_wrapped_plain(
                lines,
                width,
                format!("    - {} · {}", node.name, dfd_kind_label(node.kind)),
            );
        }
    }
}

fn append_dfd_flow_lines(lines: &mut Vec<Line<'static>>, width: usize, model: &DfdModel) {
    lines.push(Line::from(vec![Span::styled("FLOWS", theme::heading())]));
    for flow in &model.flows {
        let boundary = if !flow.boundary_ids.is_empty() {
            format!(" · boundaries: {}", flow.boundary_ids.join(", "))
        } else if flow.crosses {
            " · crosses boundary".to_string()
        } else {
            String::new()
        };
        append_wrapped_plain(
            lines,
            width,
            format!("  {} -> {} · {}{boundary}", flow.from, flow.to, flow.label),
        );
    }
}

fn summary_plain_lines(width: usize, model: &DfdModel) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return crate::renderer::empty_state_panel(
            "no system summary",
            &[hint],
            &[("threat-model:build", "describe the system and its flows")],
        );
    }
    let mut lines = Vec::new();
    append_dfd_notice(&mut lines, width, model);
    let overview = dfd_overview(model);
    append_dfd_executive_summary(&mut lines, width, &overview);
    append_dfd_zone_flows(&mut lines, width, &overview);
    append_dfd_component_tree(&mut lines, width, model, &overview);
    lines
}

fn append_dfd_notice(lines: &mut Vec<Line<'static>>, width: usize, model: &DfdModel) {
    lines.extend(
        [
            model.evidence_notice().map(str::to_owned),
            model.topology_notice(),
        ]
        .into_iter()
        .flatten()
        .flat_map(|notice| crate::renderer::shared::text::wrap_text(&notice, width))
        .into_iter()
        .map(|line| Line::styled(line, theme::label())),
    );
}

fn append_dfd_executive_summary(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    overview: &DfdOverview,
) {
    lines.push(Line::from(vec![Span::styled(
        "EXECUTIVE SUMMARY",
        theme::heading(),
    )]));
    lines.extend(
        crate::renderer::shared::text::wrap_text(&overview.executive_summary, width)
            .into_iter()
            .map(Line::from),
    );
}

fn append_dfd_zone_flows(lines: &mut Vec<Line<'static>>, width: usize, overview: &DfdOverview) {
    lines.push(Line::from(vec![Span::styled(
        "OVERALL DATA FLOW",
        theme::heading(),
    )]));
    for flow in &overview.zone_flows {
        let crossing = if flow.crossing_count > 0 {
            format!(" · {} boundary crossing(s)", flow.crossing_count)
        } else {
            String::new()
        };
        append_wrapped_plain(
            lines,
            width,
            format!(
                "  {} -> {} · {} flow(s){crossing}",
                flow.from_zone, flow.to_zone, flow.flow_count
            ),
        );
    }
}

fn append_dfd_component_tree(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    model: &DfdModel,
    overview: &DfdOverview,
) {
    lines.push(Line::from(vec![Span::styled(
        "COMPONENT TREE",
        theme::heading(),
    )]));
    append_wrapped_plain(
        lines,
        width,
        format!(
            "◇ {} · {} component(s)",
            display_target(model),
            model.nodes.len()
        ),
    );
    for (index, zone) in overview.zones.iter().enumerate() {
        append_dfd_zone(lines, width, zone, index + 1 == overview.zones.len());
    }
}

fn append_dfd_zone(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    zone: &DfdOverviewZone,
    last: bool,
) {
    let branch = if last { "└─" } else { "├─" };
    append_wrapped_plain(
        lines,
        width,
        format!(
            "{branch} {} · {} component(s)",
            zone.name,
            zone.components.len()
        ),
    );
    for (index, component) in zone.components.iter().enumerate() {
        append_dfd_component(
            lines,
            width,
            component,
            last,
            index + 1 == zone.components.len(),
        );
    }
}

fn append_dfd_component(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    component: &DfdOverviewComponent,
    zone_last: bool,
    component_last: bool,
) {
    let zone_indent = if zone_last { "   " } else { "│  " };
    let component_branch = if component_last { "└─" } else { "├─" };
    append_wrapped_plain(
        lines,
        width,
        format!(
            "{zone_indent}{component_branch} ◇ {} · {} · in {} · out {}",
            component.name,
            dfd_kind_label(component.kind),
            component.inbound_count,
            component.outgoing.len()
        ),
    );
    let child_indent = format!("{zone_indent}{}  ", if component_last { " " } else { "│" });
    append_dfd_component_children(
        lines,
        width,
        &child_indent,
        dfd_component_children(component),
    );
}

fn dfd_component_children(component: &DfdOverviewComponent) -> Vec<String> {
    let mut children = vec![format!(
        "does · {}",
        component
            .description
            .as_deref()
            .unwrap_or("not recorded in the threat model")
    )];
    children.push(format!(
        "purpose · {}",
        component
            .purpose
            .as_deref()
            .unwrap_or("not recorded; rebuild the threat model")
    ));
    children.extend(
        component
            .topology_notice()
            .map(|notice| format!("flows · {notice}")),
    );
    for flow in &component.outgoing {
        let crossing = if flow.crosses { " · boundary" } else { "" };
        children.push(format!(
            "-> {} [{}] · {}{crossing}",
            flow.target, flow.target_zone, flow.label
        ));
    }
    if let Some(context) = dfd_context_summary(component.context) {
        children.push(context);
    }
    children
}

fn append_dfd_component_children(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    indent: &str,
    children: Vec<String>,
) {
    let child_count = children.len();
    for (index, child) in children.into_iter().enumerate() {
        let branch = if index + 1 == child_count {
            "└─"
        } else {
            "├─"
        };
        append_wrapped_plain(lines, width, format!("{indent}{branch} {child}"));
    }
}

fn dfd_context_summary(counts: DfdContextCounts) -> Option<String> {
    let labels = [
        (counts.entry_points, "entry"),
        (counts.role_gates, "gate"),
        (counts.external_sinks, "sink"),
        (counts.trusted_callers, "caller"),
        (counts.assets, "asset"),
        (counts.threats, "threat"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| dfd_plain_count(count, label))
    .collect::<Vec<_>>();
    (!labels.is_empty()).then(|| format!("context · {}", labels.join(" · ")))
}

fn dfd_plain_count(count: usize, singular: &str) -> String {
    if count == 1 {
        return format!("{count} {singular}");
    }
    let plural = if singular == "entry" {
        "entries".to_string()
    } else {
        format!("{singular}s")
    };
    format!("{count} {plural}")
}

fn append_wrapped_plain(lines: &mut Vec<Line<'static>>, width: usize, value: String) {
    lines.extend(
        crate::renderer::shared::text::wrap_text(&value, width)
            .into_iter()
            .map(Line::from),
    );
}

fn dfd_kind_label(kind: DfdKind) -> &'static str {
    match kind {
        DfdKind::Entity => "entity",
        DfdKind::Process => "process",
        DfdKind::Store => "store",
    }
}

fn fit_plain(value: &str, width: usize) -> String {
    crate::renderer::shared::text::fit(value, width)
}

fn page_tagline(page: VizPage) -> &'static str {
    match page {
        VizPage::AttackSurface => "risk density as 3D relief — peaks are the hottest modules",
        VizPage::AttackPath => "how tainted input reaches a dangerous sink, stage by stage",
        VizPage::Summary => "why the system exists and how its parts move data",
        VizPage::Dfd => "data flows across trust boundaries — crossings are where STRIDE lives",
        VizPage::EntryPoints => "trust-zone browser — select an ingress to inspect its evidence",
        VizPage::Components => {
            "repository stack tree — declared constraints and resolved versions stay distinct"
        }
        VizPage::Heatmap => "severity × module — where findings concentrate",
        VizPage::ExploitChain => "entry → impact as an attack tree with AND/OR steps",
        VizPage::Worklist => "highest-risk files first — every row cites the rankers behind it",
    }
}

fn compact_page_tagline(page: VizPage) -> &'static str {
    match page {
        VizPage::AttackSurface => "module risk peaks",
        VizPage::AttackPath => "source-to-sink path",
        VizPage::Summary => "system purpose + shape",
        VizPage::Dfd => "trust-boundary flows",
        VizPage::EntryPoints => "select an ingress",
        VizPage::Components => "stack + versions",
        VizPage::Heatmap => "findings by module",
        VizPage::ExploitChain => "entry-to-impact tree",
        VizPage::Worklist => "riskiest files first",
    }
}

fn responsive_header_line(
    full: &str,
    compact: &str,
    width: usize,
    style: ratatui::style::Style,
) -> Line<'static> {
    let value = if full.chars().count() <= width {
        full
    } else {
        compact
    };
    Line::styled(fit_plain(value, width), style)
}

fn responsive_nav_line(
    prefix: &'static str,
    available: &[VizPage],
    page: VizPage,
    width: usize,
    suffix: &'static str,
) -> Line<'static> {
    let full = Line::from(nav_spans_for_pages(prefix, available, page, suffix));
    if full.width() <= width {
        return full;
    }
    let position = page_position_label(available, page);
    let label = page_nav_label(page);
    let compact = format!("{prefix} [{label}]{position} · Tab");
    if compact.chars().count() <= width {
        return Line::styled(compact, theme::muted());
    }
    Line::styled(
        fit_plain(&format!("[{label}]{position}"), width),
        theme::muted(),
    )
}

fn page_position_label(available: &[VizPage], page: VizPage) -> String {
    available
        .iter()
        .position(|candidate| *candidate == page)
        .map(|index| format!(" · {}/{}", index + 1, available.len()))
        .unwrap_or_default()
}

#[cfg(test)]
fn nav_spans(app: &ShellApp, page: VizPage) -> Vec<Span<'static>> {
    nav_spans_for_pages("pages", &app.active_viz_pages(), page, "Tab cycles")
}

fn nav_spans_for_pages(
    prefix: &'static str,
    available: &[VizPage],
    page: VizPage,
    suffix: &'static str,
) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(format!("{prefix}  "), theme::muted())];
    append_page_tabs(&mut spans, &available, page);
    if available.len() > 1 {
        spans.push(Span::styled(format!("  ·  {suffix}"), theme::muted()));
    }
    spans
}

fn append_page_tabs(spans: &mut Vec<Span<'static>>, pages: &[VizPage], active: VizPage) {
    for (index, page) in pages.iter().copied().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ".to_string(), theme::subtle()));
        }
        spans.push(page_tab_span(page, active));
    }
}

fn page_tab_span(page: VizPage, active: VizPage) -> Span<'static> {
    let label = page_nav_label(page);
    if page == active {
        Span::styled(format!("[{label}]"), theme::accent())
    } else {
        Span::styled(label.to_string(), theme::muted())
    }
}

fn page_nav_label(page: VizPage) -> &'static str {
    match page {
        VizPage::AttackSurface => "terrain",
        VizPage::AttackPath => "path",
        VizPage::Summary => "summary",
        VizPage::Dfd => "dfd",
        VizPage::EntryPoints => "entry",
        VizPage::Components => "components",
        VizPage::Heatmap => "heatmap",
        VizPage::ExploitChain => "chain",
        VizPage::Worklist => "worklist",
    }
}

fn attack_surface_plain_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        "3D terrain renders in a TTY — showing the module heatmap instead",
        theme::muted(),
    )])];
    lines.extend(heatmap_lines(width, &cached_findings_heatmap(app)));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_empty_gallery_does_not_invent_a_tab_position() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Scene);
        app.router.scene_mut().set_page(VizPage::Worklist);
        assert!(!app.active_viz_pages().contains(&VizPage::Worklist));
        let title = gallery_viewport_header_lines(&app, Rect::new(0, 0, 40, 10));
        assert!(title[0].to_string().contains("RISK WORKLIST"));
        assert!(!title[0].to_string().contains("1/2"));
        let nav = responsive_nav_line(
            "pages",
            &app.active_viz_pages(),
            VizPage::Worklist,
            25,
            "Tab cycles",
        );
        assert!(!nav.to_string().contains("1/2"));
        app.router.scene_mut().set_page(VizPage::Dfd);
        let title = gallery_viewport_header_lines(&app, Rect::new(0, 0, 40, 10));
        assert!(title[0].to_string().contains("2/2"));
    }
    use kuzushi_core::{save_persistent_threat_model, V2Config, WorkspaceTarget};
    use serde_json::json;

    #[test]
    fn dfd_page_plain_lines_list_nodes_and_edges() {
        let temp = tempfile::tempdir().expect("temp target");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        save_persistent_threat_model(temp.path(), &sample_dfd_doc(), true).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();

        let lines = scene_page_lines(&app, Rect::new(0, 0, 80, 24), VizPage::Dfd);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        // Crossing count is boundary-tag derived (zone fallback only for
        // untagged flows) and must match the frame legend's count.
        assert!(
            text.contains("DFD · 3 nodes · 2 flows · 3 zones · 1 boundary crossings"),
            "{text}"
        );
        assert!(text.contains("NODES"));
        assert!(text.contains("FLOWS"));
        assert!(text.contains("Browser · entity"));
        assert!(text.contains("API server · process"));
        assert!(text.contains("Browser -> API server · https · boundaries: tb-edge"));
        assert!(
            text.contains("API server -> Postgres · sql\n")
                || text.contains("API server -> Postgres · sql"),
            "explicitly boundary-free flow must not claim a crossing: {text}"
        );
        assert!(!text.contains("Postgres · sql · crosses boundary"));
    }

    #[test]
    fn summary_page_explains_system_and_component_purpose() {
        let temp = tempfile::tempdir().expect("temp target");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        save_persistent_threat_model(temp.path(), &sample_dfd_doc(), true).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();

        let lines = scene_page_lines(&app, Rect::new(0, 0, 80, 24), VizPage::Summary);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("EXECUTIVE SUMMARY"), "{text}");
        assert!(
            text.contains("Operators use Sample to review requests"),
            "{text}"
        );
        assert!(text.contains("OVERALL DATA FLOW"), "{text}");
        assert!(text.contains("COMPONENT TREE"), "{text}");
        assert!(text.contains("does · Handles browser requests"), "{text}");
        assert!(
            text.contains("purpose · Applies the product's review policy"),
            "{text}"
        );
    }

    #[test]
    fn empty_gallery_header_only_shows_the_permanent_summary_and_dfd_pages() {
        let app = ShellApp::new(V2Config::default(), None);

        let text = spans_text(nav_spans(&app, VizPage::Dfd));

        // Summary and DFD are guidance surfaces that stay reachable without an
        // artifact, so an empty gallery has exactly those two Tab stops and
        // advertises the cycle.
        assert!(text.contains("pages  summary · [dfd]"), "{text}");
        assert!(text.contains("Tab cycles"), "{text}");
        // Every content-gated page stays out of the nav until its artifact lands.
        assert!(!text.contains("terrain"), "{text}");
        assert!(!text.contains("path"), "{text}");
        assert!(!text.contains("entry"), "{text}");
        assert!(!text.contains("components"), "{text}");
        assert!(!text.contains("heatmap"), "{text}");
        assert!(!text.contains("chain"), "{text}");
        assert!(!text.contains("worklist"), "{text}");
        assert!(!text.contains('∅'), "{text}");
        assert!(!text.contains("Esc/q"), "{text}");
        assert!(!text.contains("j/k"), "{text}");
        assert!(!text.contains("PgUp"), "{text}");
    }

    #[test]
    fn gallery_header_compacts_without_crossing_the_terminal_width() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_scene_page(VizPage::Dfd);

        let lines = gallery_header_lines(&app, 20);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(lines.iter().all(|line| line.width() <= 20), "{text}");
        assert!(text.contains("DATA-FLOW"), "{text}");
        assert!(text.contains("trust-boundary flows"), "{text}");
        assert!(text.contains("[dfd]"), "{text}");
    }

    #[test]
    fn gallery_navigation_reserves_view_controls_for_the_footer() {
        let app = ShellApp::new(V2Config::default(), None);

        let text = spans_text(nav_spans(&app, VizPage::AttackSurface));

        assert!(text.contains("pages"), "{text}");
        assert!(!text.contains("static"), "{text}");
        assert!(!text.contains("spinning"), "{text}");
        assert!(!text.contains("Esc/q"), "{text}");
        assert!(!text.contains("pause"), "{text}");
    }

    #[test]
    fn attack_surface_plain_lines_name_empty_state() {
        let app = ShellApp::new(V2Config::default(), None);

        let lines = scene_page_lines(&app, Rect::new(0, 0, 80, 24), VizPage::AttackSurface);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("no heatmap data"), "{text}");
        assert!(text.contains("run `scan`"), "{text}");
    }

    #[test]
    fn every_empty_gallery_page_names_an_actionable_prerequisite() {
        let app = ShellApp::new(V2Config::default(), None);
        let cases = [
            (VizPage::AttackSurface, "scan"),
            (VizPage::AttackPath, "taint-iris:hunt"),
            (VizPage::Summary, "threat-model:build"),
            (VizPage::Dfd, "threat-model:build"),
            (VizPage::EntryPoints, "threat-model:build"),
            (VizPage::Components, "sbom-scan:scan"),
            (VizPage::Heatmap, "scan"),
            (VizPage::ExploitChain, "exploit-chain:scan"),
        ];

        for (page, command) in cases {
            let lines = scene_page_lines(&app, Rect::new(0, 0, 96, 24), page);
            let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
            assert!(text.contains(command), "{page:?} missing {command}: {text}");
        }
    }

    #[test]
    fn attack_surface_plain_lines_project_heatmap_data() {
        let mut app = ShellApp::new(V2Config::default(), None);
        *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
            "rule.high",
            "src/auth/login.rs",
            10,
            Some(10),
            kuzushi_core::Severity::High,
            "auth bug",
        )];

        let lines = scene_page_lines(&app, Rect::new(0, 0, 80, 24), VizPage::AttackSurface);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("module"), "{text}");
        assert!(text.contains("auth"), "{text}");
        assert!(!text.contains("renders only in an interactive"), "{text}");
    }

    #[test]
    fn exploit_chain_plain_lines_list_chain_steps() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.domain_mut()
            .set_exploit_chains(vec![crate::ExploitChainDetail {
                id: "chain-1".to_string(),
                title: "template render to RCE".to_string(),
                severity: crate::ChainSeverity::Critical,
                narrative: Some("request template reaches renderer".to_string()),
                impact_description: Some("remote code execution".to_string()),
                preconditions: vec!["attacker can submit template name".to_string()],
                steps: vec![crate::ExploitChainStep {
                    role: "source".to_string(),
                    description: "attacker controls template name".to_string(),
                    file: "app.js".to_string(),
                    line: 12,
                }],
            }]);

        let lines = scene_page_lines(&app, Rect::new(0, 0, 96, 24), VizPage::ExploitChain);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("ATTACK TREE · 1 chains"), "{text}");
        assert!(text.contains("[critical] template render to RCE"), "{text}");
        assert!(text.contains("attacker controls template name"), "{text}");
        assert!(text.contains("remote code execution"), "{text}");
        assert!(!text.contains("renders only in an interactive"), "{text}");
    }

    #[test]
    fn entry_points_page_breaks_down_every_discovered_ingress_surface() {
        let temp = tempfile::tempdir().expect("temp target");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        save_persistent_threat_model(temp.path(), &sample_dfd_doc(), true).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();

        let lines = scene_page_lines(&app, Rect::new(0, 0, 80, 30), VizPage::EntryPoints);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        let nav = spans_text(nav_spans(&app, VizPage::EntryPoints));

        assert!(
            text.contains("ENTRY POINTS · 0 extracted · 1 modeled · 0 overlap · 1 union"),
            "{text}"
        );
        assert!(text.contains("MODEL ONLY · 1"), "{text}");
        assert!(text.contains("[http route]"), "{text}");
        assert!(text.contains("POST /login"), "{text}");
        assert!(text.contains("Browser"), "{text}");
        assert!(text.contains("src/login.rs:42"), "{text}");
        assert!(nav.contains("dfd · [entry]"), "{nav}");
    }

    fn sample_dfd_doc() -> serde_json::Value {
        json!({
            "systemContext": "Operators use Sample to review requests before approved records are stored.",
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "type": "external entity", "trustZone": "internet",
                     "description": "Collects operator requests", "purpose": "Provides the operator surface"},
                    {"id": "api", "name": "API server", "type": "process", "trustZone": "app-tier",
                     "description": "Handles browser requests", "purpose": "Applies the product's review policy"},
                    {"id": "db", "name": "Postgres", "type": "data store", "trustZone": "data-tier",
                     "description": "Stores approved records", "purpose": "Preserves durable review state"}
                ],
                "flows": [
                    {"id": "f1", "sourceId": "user", "targetId": "api", "description": "https",
                     "trustBoundaryIds": ["tb-edge"]},
                    {"id": "f2", "sourceId": "api", "targetId": "db", "description": "sql",
                     "trustBoundaryIds": []}
                ],
                "trustBoundaries": [
                    {"id": "tb-edge", "name": "Internet to app", "outerZone": "internet",
                     "innerZone": "app-tier", "crossingFlowIds": ["f1"]}
                ]
            },
            "attackSurface": {
                "entryPoints": [
                    {
                        "id": "EP-1", "name": "POST /login", "kind": "http_route",
                        "method": "POST", "route": "/login", "trustZone": "internet",
                        "path": "src/login.rs", "line": 42,
                        "description": "Accepts login credentials",
                        "evidence": "src/login.rs:42 router.post",
                        "targetElementIds": ["user", "tb-edge"]
                    }
                ]
            }
        })
    }

    fn line_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    fn spans_text(spans: Vec<Span<'static>>) -> String {
        spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>()
    }
}

#[cfg(test)]
mod topology_tests;
