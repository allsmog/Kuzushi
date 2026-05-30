//! The security-viz gallery: a shared header plus page dispatch. The 3D
//! attack-surface page is drawn frame-level (see `render_scene_view`); every
//! other page is a 2D box-drawing diagram rendered here as styled lines.

use super::diagrams::{attack_path_lines, heatmap_lines};
use super::*;
use crate::scene3d::VizPage;
use crate::theme;
use crate::ui_view_models::{findings_heatmap, taint_flow_path};
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
        Line::from(vec![Span::styled(page_tagline(page).to_string(), theme::muted())]),
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
        VizPage::AttackSurface => frame_only_lines("3D relief"),
        VizPage::Dfd => frame_only_lines("node-link data-flow graph"),
        VizPage::ExploitChain => frame_only_lines("attack tree"),
    }
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
        let motion = if app.scene_paused { "paused" } else { "spinning" };
        spans.push(Span::styled(
            format!("  ·  {motion} · space pause · hjkl rotate"),
            theme::muted(),
        ));
    }
    spans.push(Span::styled("  ·  esc back".to_string(), theme::muted()));
    spans
}

/// Plain / non-TTY fallback for the frame-rendered pages (their braille/half-
/// block graphics only paint in a real terminal).
fn frame_only_lines(kind: &str) -> Vec<Line<'static>> {
    vec![Line::from(vec![Span::styled(
        format!("the {kind} renders only in an interactive truecolor terminal."),
        theme::muted(),
    )])]
}
