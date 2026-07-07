//! The security-viz gallery: a shared header plus page dispatch. The 3D
//! attack-surface page is drawn frame-level (see `render_scene_view`); every
//! other page is a 2D box-drawing diagram rendered here as styled lines.

use super::diagrams::{attack_path_lines, heatmap_lines};
use super::*;
use crate::scene3d::VizPage;
use crate::theme;
use crate::ui_view_models::{
    attack_tree, cached_findings_heatmap, dfd_model, taint_flow_path, AttackTree, DfdKind, DfdModel,
};
use crate::ChainSeverity;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

/// The 3-row header shown above every gallery page: title, tagline, page nav.
/// Shared by the 3D frame renderer and the 2D line pages so they stay aligned.
pub(crate) fn gallery_header_lines(app: &ShellApp) -> Vec<Line<'static>> {
    let page = app.router.scene().page();
    vec![
        Line::from(vec![Span::styled(
            format!("◆ KUZUSHI VIZ — {}", page.label().to_uppercase()),
            theme::heading(),
        )]),
        Line::from(vec![Span::styled(
            page_tagline(page).to_string(),
            theme::muted(),
        )]),
        Line::from(nav_spans(app, page)),
    ]
}

/// Line-based entry for the gallery (2D pages always; the 3D page only in plain
/// / non-TTY mode, where the framebuffer can't run).
pub(crate) fn scene_page_lines(app: &ShellApp, area: Rect, page: VizPage) -> Vec<Line<'static>> {
    let mut lines = gallery_header_lines(app);
    lines.push(Line::from(String::new()));
    lines.extend(page_body_lines(app, area, page));
    lines
}

fn page_body_lines(app: &ShellApp, area: Rect, page: VizPage) -> Vec<Line<'static>> {
    let width = area.width as usize;
    match page {
        VizPage::AttackPath => attack_path_lines(width, &taint_flow_path(app)),
        VizPage::Heatmap => heatmap_lines(width, &cached_findings_heatmap(app)),
        // Frame-rendered pages (3D terrain + box-drawing graph/tree) can't draw
        // in the line/plain path; show a short note instead.
        VizPage::AttackSurface => attack_surface_plain_lines(app, width),
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
    let mut lines = vec![Line::from(vec![Span::styled(
        format!(
            "DFD · {} nodes · {} flows · {} zones",
            model.nodes.len(),
            model.flows.len(),
            model.zones.len()
        ),
        theme::accent(),
    )])];
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
            lines.push(Line::from(vec![Span::raw(fit_plain(
                &format!("    - {} · {}", node.name, dfd_kind_label(node.kind)),
                width,
            ))]));
        }
    }
}

fn append_dfd_flow_lines(lines: &mut Vec<Line<'static>>, width: usize, model: &DfdModel) {
    lines.push(Line::from(vec![Span::styled("FLOWS", theme::heading())]));
    for flow in &model.flows {
        let boundary = if flow.crosses {
            " · crosses boundary"
        } else {
            ""
        };
        lines.push(Line::from(vec![Span::raw(fit_plain(
            &format!(
                "  {} -> {} · {}{}",
                flow.from, flow.to, flow.label, boundary
            ),
            width,
        ))]));
    }
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
        VizPage::Dfd => "data flows across trust boundaries — crossings are where STRIDE lives",
        VizPage::Heatmap => "severity × module — where findings concentrate",
        VizPage::ExploitChain => "entry → impact as an attack tree with AND/OR steps",
    }
}

fn nav_spans(app: &ShellApp, page: VizPage) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled("pages  ".to_string(), theme::muted())];
    append_page_tabs(&mut spans, app, page);
    spans.push(Span::styled("  ·  Tab cycles".to_string(), theme::muted()));
    if page.is_3d() {
        let motion = if app.router.scene().paused() {
            "paused"
        } else if app.scene_animating() {
            "spinning"
        } else {
            "static"
        };
        spans.push(Span::styled(
            format!("  ·  {motion} · space pause · hjkl rotate"),
            theme::muted(),
        ));
    }
    spans.push(Span::styled(
        "  ·  Esc/q return".to_string(),
        theme::muted(),
    ));
    spans
}

fn append_page_tabs(spans: &mut Vec<Span<'static>>, app: &ShellApp, active: VizPage) {
    for (index, page) in VizPage::ALL.iter().copied().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ".to_string(), theme::subtle()));
        }
        spans.push(page_tab_span(app, page, active));
    }
}

fn page_tab_span(app: &ShellApp, page: VizPage, active: VizPage) -> Span<'static> {
    let mut label = page_nav_label(page).to_string();
    if !page_has_content(app, page) {
        label.push('·');
    }
    if page == active {
        Span::styled(format!("[{label}]"), theme::accent())
    } else {
        Span::styled(label, theme::muted())
    }
}

fn page_nav_label(page: VizPage) -> &'static str {
    match page {
        VizPage::AttackSurface => "terrain",
        VizPage::AttackPath => "path",
        VizPage::Dfd => "dfd",
        VizPage::Heatmap => "heatmap",
        VizPage::ExploitChain => "chain",
    }
}

fn page_has_content(app: &ShellApp, page: VizPage) -> bool {
    match page {
        VizPage::AttackSurface | VizPage::Heatmap => !app.findings().is_empty(),
        VizPage::AttackPath => app.domain().taint_flow().is_some(),
        VizPage::Dfd => dfd_model(app).empty_hint.is_none(),
        VizPage::ExploitChain => app.domain().has_exploit_chains(),
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
    use kuzushi_core::{save_persistent_threat_model, V2Config, WorkspaceTarget};
    use serde_json::json;

    #[test]
    fn dfd_page_plain_lines_list_nodes_and_edges() {
        let temp = tempfile::tempdir().expect("temp target");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        save_persistent_threat_model(temp.path(), &sample_dfd_doc(), true).unwrap();
        let app = ShellApp::new(V2Config::default(), Some(&workspace));

        let lines = scene_page_lines(&app, Rect::new(0, 0, 80, 24), VizPage::Dfd);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("DFD · 3 nodes · 2 flows · 3 zones"));
        assert!(text.contains("Browser · entity"));
        assert!(text.contains("API server · process"));
        assert!(text.contains("Browser -> API server · https · crosses boundary"));
    }

    #[test]
    fn attack_surface_nav_reports_static_when_scene_is_not_animating() {
        let app = ShellApp::new(V2Config::default(), None);

        let text = spans_text(nav_spans(&app, VizPage::AttackSurface));

        assert!(text.contains("static"), "{text}");
        assert!(!text.contains("spinning"), "{text}");
        assert!(text.contains("Esc/q return"), "{text}");
        assert!(!text.contains("o return"), "{text}");
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

    fn sample_dfd_doc() -> serde_json::Value {
        json!({
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "type": "external entity", "trustZone": "internet"},
                    {"id": "api", "name": "API server", "type": "process", "trustZone": "app-tier"},
                    {"id": "db", "name": "Postgres", "type": "data store", "trustZone": "data-tier"}
                ],
                "flows": [
                    {"id": "f1", "sourceId": "user", "targetId": "api", "description": "https"},
                    {"id": "f2", "sourceId": "api", "targetId": "db", "description": "sql"}
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
