//! The security-viz gallery: a shared header plus page dispatch. The 3D
//! attack-surface page is drawn frame-level (see `render_scene_view`); every
//! other page is a 2D box-drawing diagram rendered here as styled lines.

use super::diagrams::{attack_path_lines, heatmap_lines};
use super::*;
use crate::scene3d::VizPage;
use crate::theme;
use crate::ui_view_models::{
    attack_tree, dfd_model, findings_heatmap, taint_flow_path, AttackTree, DfdKind, DfdModel,
};
use crate::ChainSeverity;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

/// The 3-row header shown above every gallery page: title, tagline, page nav.
/// Shared by the 3D frame renderer and the 2D line pages so they stay aligned.
pub(crate) fn gallery_header_lines(app: &ShellApp) -> Vec<Line<'static>> {
    let page = app.scene_page;
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
        VizPage::Heatmap => heatmap_lines(width, &findings_heatmap(&app.findings)),
        // Frame-rendered pages (3D terrain + box-drawing graph/tree) can't draw
        // in the line/plain path; show a short note instead.
        VizPage::AttackSurface => attack_surface_plain_lines(app, width),
        VizPage::Dfd => dfd_plain_lines(width, &dfd_model(app)),
        VizPage::ExploitChain => exploit_chain_plain_lines(width, &attack_tree(app)),
    }
}

fn exploit_chain_plain_lines(width: usize, model: &AttackTree) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return vec![Line::from(vec![Span::styled(
            fit_plain(hint, width),
            theme::muted(),
        )])];
    }
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("ATTACK TREE · {} chains", model.chains.len()),
        theme::accent(),
    )])];
    for (index, chain) in model.chains.iter().enumerate() {
        lines.push(Line::from(vec![Span::raw(fit_plain(
            &format!(
                "  {}. [{}] {}",
                index + 1,
                chain_severity_label(chain.severity),
                chain.title
            ),
            width,
        ))]));
        for (step_index, step) in chain.steps.iter().enumerate() {
            lines.push(Line::from(vec![Span::raw(fit_plain(
                &format!("      {}. {}", step_index + 1, step),
                width,
            ))]));
        }
    }
    lines
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
        return vec![Line::from(vec![Span::styled(
            fit_plain(hint, width),
            theme::muted(),
        )])];
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
    let index = VizPage::ALL.iter().position(|p| *p == page).unwrap_or(0) + 1;
    let total = VizPage::ALL.len();
    let mut spans = vec![
        Span::styled(format!("page {index}/{total}"), theme::accent()),
        Span::styled("  ·  Tab cycles".to_string(), theme::muted()),
    ];
    if page.is_3d() {
        let motion = if app.scene_paused {
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

fn attack_surface_plain_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    if app.findings.is_empty() {
        return vec![Line::from(vec![Span::styled(
            fit_plain(
                "no risk surface yet — run `scan` to populate findings.",
                width,
            ),
            theme::muted(),
        )])];
    }
    frame_only_lines("3D relief")
}

/// Plain / non-TTY fallback for the frame-rendered pages (their braille/half-
/// block graphics only paint in a real terminal).
fn frame_only_lines(kind: &str) -> Vec<Line<'static>> {
    vec![Line::from(vec![Span::styled(
        format!("the {kind} renders only in an interactive truecolor terminal."),
        theme::muted(),
    )])]
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

        assert!(text.contains("no risk surface yet"), "{text}");
        assert!(text.contains("run `scan`"), "{text}");
    }

    #[test]
    fn exploit_chain_plain_lines_list_chain_steps() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.exploit_chains = vec![crate::ExploitChainDetail {
            id: "chain-1".to_string(),
            title: "template render to RCE".to_string(),
            severity: crate::ChainSeverity::Critical,
            steps: vec![crate::ExploitChainStep {
                role: "source".to_string(),
                description: "attacker controls template name".to_string(),
                file: "app.js".to_string(),
                line: 12,
            }],
        }];

        let lines = scene_page_lines(&app, Rect::new(0, 0, 96, 24), VizPage::ExploitChain);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("ATTACK TREE · 1 chains"), "{text}");
        assert!(text.contains("[critical] template render to RCE"), "{text}");
        assert!(text.contains("attacker controls template name"), "{text}");
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
