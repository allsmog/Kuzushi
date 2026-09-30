//! Renders a `Scene` into a half-block truecolor framebuffer (two square pixels
//! per cell via `▀`) with text labels overlaid. The actual rasterization (z-
//! buffer, shading, fog, glow) is pure and lives in `scene3d::render`; this file
//! is just the ratatui glue: header, framebuffer→cells, label stamping.

use super::diagram::{DfdDiagram, DfdSummary, TreeDiagram};
use super::entry_points::EntryPointBrowser;
use super::gallery::{gallery_header_lines, map_gallery_header_lines, page_body_lines};
use super::scene_color::to_color;
use super::*;
use crate::scene3d::{
    active_palette, attack_surface_scene, brighten, render_to_framebuffer, Camera, Projector,
    SceneLabel, VizPage, BACKGROUND,
};
use crate::ui_view_models::{attack_tree, cached_risk_by_module, dfd_model, entry_point_breakdown};
use ratatui::layout::Rect;
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Paragraph, Wrap};

const CAM_DISTANCE: f32 = 4.2;

/// Frame-level renderer for the frame-rendered gallery pages: the 3D terrain
/// (half-block framebuffer) and the two Canvas diagrams (DFD graph, attack
/// tree). The line-based pages never reach here.
pub(crate) fn render_scene_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let outer = super::gallery_layout::gallery_sections(area, false);
    frame.render_widget(
        Paragraph::new(gallery_header_lines(app, area.width as usize)),
        outer[0],
    );
    render_scene_body(frame, outer[1], app, app.router.scene().page(), 0);
}

/// Render the same gallery inside Map. `z` promotes this exact projection to
/// the full-frame Scene view; there is no second, weaker Map visualization.
pub(crate) fn render_embedded_map_gallery(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    line_scroll: u16,
) {
    let outer = super::gallery_layout::gallery_sections(area, true);
    frame.render_widget(
        Paragraph::new(map_gallery_header_lines(app, area.width as usize)),
        outer[0],
    );
    render_scene_body(
        frame,
        outer[1],
        app,
        app.current_map_viz_page(),
        line_scroll,
    );
}

fn render_scene_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    page: VizPage,
    line_scroll: u16,
) {
    match page {
        VizPage::Summary => render_summary_body(frame, area, app),
        VizPage::Dfd => render_dfd_body(frame, area, app),
        VizPage::ExploitChain => render_exploit_chain_body(frame, area, app),
        VizPage::EntryPoints => render_entry_points_body(frame, area, app),
        VizPage::AttackSurface => render_terrain_body(frame, area, app),
        VizPage::AttackPath | VizPage::Components | VizPage::Heatmap | VizPage::Worklist => {
            render_line_page_body(frame, area, app, page, line_scroll)
        }
    }
}

fn render_summary_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    frame.render_widget(
        DfdSummary {
            model: dfd_model(app),
            component_selection: app.router.scene().summary_component_selection(),
            scroll: app.router.scene().summary_scroll(),
        },
        area,
    );
}

fn render_dfd_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    frame.render_widget(
        DfdDiagram {
            model: dfd_model(app),
            selection: Some(app.router.scene().dfd_selection()),
            detail_scroll: app.router.scene().dfd_detail_scroll(),
            focused: app.router.scene().dfd_focused(),
            context_selection: app.router.scene().dfd_context_selection(),
        },
        area,
    );
}

fn render_exploit_chain_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    frame.render_widget(
        TreeDiagram {
            model: attack_tree(app),
        },
        area,
    );
}

fn render_entry_points_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    frame.render_widget(
        EntryPointBrowser {
            model: entry_point_breakdown(app),
            selection: app.router.scene().entry_point_selection(),
            detail_scroll: app.router.scene().entry_point_detail_scroll(),
        },
        area,
    );
}

fn render_line_page_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    page: VizPage,
    line_scroll: u16,
) {
    let lines = page_body_lines(app, area, page);
    let Some(window) =
        super::gallery_layout::line_page_window(area.height, lines.len(), line_scroll)
    else {
        render_scrolled_lines(frame, area, lines, 0);
        return;
    };
    let sections = super::gallery_layout::line_page_position_sections(area);
    render_scrolled_lines(frame, sections[0], lines, window.start);
    frame.render_widget(
        Paragraph::new(Line::styled(window.position_label, crate::theme::muted())),
        sections[1],
    );
}

fn render_scrolled_lines(
    frame: &mut Frame<'_>,
    area: Rect,
    lines: Vec<Line<'static>>,
    scroll: u16,
) {
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

// ── 3D terrain body: rasterize via scene3d, then overlay labels ────────────

fn render_terrain_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let (cols, rows) = (area.width as usize, area.height as usize);
    if cols == 0 || rows == 0 {
        return;
    }
    if app.findings().is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                "no risk surface yet — run `scan` to populate findings.",
                crate::theme::muted(),
            )])),
            area,
        );
        return;
    }
    let scene = attack_surface_scene(&cached_risk_by_module(app));
    let cam = scene_camera(app);
    let fb = render_to_framebuffer(&scene, cam, cols, rows * 2);
    let proj = Projector::new(cam, cols, rows * 2);
    let mut cells = build_cells(&fb, rows, cols);
    stamp_labels(&mut cells, &proj, &scene.labels);
    let lines = cells.into_iter().map(row_to_line).collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn scene_camera(app: &ShellApp) -> Camera {
    Camera {
        yaw: app.router.scene().yaw(),
        pitch: app.router.scene().pitch(),
        distance: CAM_DISTANCE,
    }
}

// ── Framebuffer → cells → lines (with label overlay) ──────────────────────

struct Cell {
    ch: char,
    fg: Color,
    bg: Color,
}

fn build_cells(fb: &crate::scene3d::Framebuffer, rows: usize, cols: usize) -> Vec<Vec<Cell>> {
    (0..rows)
        .map(|r| {
            (0..cols)
                .map(|c| Cell {
                    ch: '▀',
                    fg: to_color(fb.pixel(c, r * 2)),
                    bg: to_color(fb.pixel(c, r * 2 + 1)),
                })
                .collect()
        })
        .collect()
}

fn stamp_labels(cells: &mut [Vec<Cell>], proj: &Projector, labels: &[SceneLabel]) {
    let bg_color = to_color(BACKGROUND);
    for lbl in labels {
        let Some((px, py, _)) = proj.pixel(lbl.at) else {
            continue;
        };
        let cy = (py * 0.5).round() as i32;
        let cx = px.round() as i32 + 1;
        let fg = to_color(brighten(active_palette(lbl.color)));
        stamp(cells, cx, cy, &lbl.text, fg, bg_color);
    }
}

fn stamp(cells: &mut [Vec<Cell>], cx: i32, cy: i32, text: &str, fg: Color, bg: Color) {
    if cy < 0 || cy as usize >= cells.len() {
        return;
    }
    let row = &mut cells[cy as usize];
    for (k, ch) in text.chars().enumerate() {
        let x = cx + k as i32;
        if x >= 0 && (x as usize) < row.len() {
            row[x as usize] = Cell { ch, fg, bg };
        }
    }
}

/// Merge runs of cells sharing fg+bg into single spans (the background collapses
/// to one span; lit pixels stay small clusters).
fn row_to_line(row: Vec<Cell>) -> Line<'static> {
    let mut spans = Vec::new();
    let mut cells = row.into_iter();
    let Some(first) = cells.next() else {
        return Line::from(String::new());
    };
    let (mut fg, mut bg, mut buf) = (first.fg, first.bg, first.ch.to_string());
    for cell in cells {
        if cell.fg == fg && cell.bg == bg {
            buf.push(cell.ch);
        } else {
            spans.push(styled(buf, fg, bg));
            (fg, bg, buf) = (cell.fg, cell.bg, cell.ch.to_string());
        }
    }
    spans.push(styled(buf, fg, bg));
    Line::from(spans)
}

fn styled(text: String, fg: Color, bg: Color) -> Span<'static> {
    if crate::theme::active_theme().no_color {
        return Span::styled(text, Style::default());
    }
    Span::styled(text, Style::default().fg(fg).bg(bg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{StampedTargetCandidateFacts, TargetCandidateFacts};
    use kuzushi_core::{SbomComponent, SbomLockfile, SbomScanReport, V2Config, WorkspaceTarget};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// The audit reproduced this on a 2657-row component tree: the embedded
    /// canvas cut the tree off mid-branch with no indicator, so nothing on
    /// screen said the rest existed. `z` zoom disclosed the true count.
    #[test]
    fn the_embedded_component_tree_states_how_much_it_is_hiding() {
        let (temp, mut app) = app_with_component_inventory();
        app.router.scene_mut().set_page(VizPage::Components);
        assert_eq!(app.current_map_viz_page(), VizPage::Components);

        let rendered = render_embedded_gallery(&app, 60, 10, 0);

        let position = rendered.last().expect("a rendered canvas").trim_end();
        assert_eq!(position, " rows 1-7/16", "{rendered:#?}");
        drop(temp);
    }

    /// `G` sets the surface scroll to `u16::MAX`; an unclamped `Paragraph`
    /// scroll answered that with an empty canvas.
    #[test]
    fn scrolling_the_embedded_component_tree_to_the_end_keeps_content_on_screen() {
        let (temp, mut app) = app_with_component_inventory();
        app.router.scene_mut().set_page(VizPage::Components);

        let rendered = render_embedded_gallery(&app, 60, 10, u16::MAX);

        assert!(
            rendered[2..rendered.len() - 1]
                .iter()
                .any(|row| !row.trim().is_empty()),
            "the last page must show the tree's tail, not blank rows: {rendered:#?}"
        );
        let position = rendered.last().expect("a rendered canvas").trim_end();
        assert_eq!(position, " rows 10-16/16", "{rendered:#?}");
        drop(temp);
    }

    /// A projection that fits states nothing — the disclosure is a truncation
    /// signal, not permanent chrome.
    #[test]
    fn a_component_tree_that_fits_its_canvas_states_no_position() {
        let (temp, mut app) = app_with_component_inventory();
        app.router.scene_mut().set_page(VizPage::Components);

        let rendered = render_embedded_gallery(&app, 60, 40, 0);

        assert!(
            !rendered.iter().any(|row| row.contains("rows ")),
            "a page that fits must not claim a window: {rendered:#?}"
        );
        drop(temp);
    }

    fn render_embedded_gallery(
        app: &ShellApp,
        width: u16,
        height: u16,
        line_scroll: u16,
    ) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| {
                render_embedded_map_gallery(frame, frame.area(), app, line_scroll);
            })
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn app_with_component_inventory() -> (tempfile::TempDir, ShellApp) {
        let temp = tempfile::tempdir().expect("temp target");
        let workspace = WorkspaceTarget::new(temp.path()).expect("workspace");
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let path = temp.path().to_path_buf();
        app.session_mut().begin_active_target_facts(path.clone(), 1);
        assert!(app
            .session_mut()
            .apply_active_target_facts(StampedTargetCandidateFacts {
                generation: 1,
                facts: component_facts(path),
            }));
        (temp, app)
    }

    fn component_facts(path: PathBuf) -> TargetCandidateFacts {
        TargetCandidateFacts {
            path,
            repository_kind: "git repository".into(),
            branch: None,
            revision: None,
            dirty: None,
            languages: vec!["Rust".into()],
            build_systems: vec!["Cargo".into()],
            nested_scopes: Vec::new(),
            file_count: 12,
            file_count_capped: false,
            prior_artifact_count: 0,
            prior_artifacts: Vec::new(),
            component_inventory: Some(component_report()),
            component_inventory_error: None,
        }
    }

    fn component_report() -> SbomScanReport {
        let components = (0..8)
            .map(|index| SbomComponent {
                name: format!("crate-{index}"),
                version: Some(format!("1.{index}.0")),
                package_url: None,
                ecosystem: "cargo".into(),
                manifest_path: "Cargo.toml".into(),
                scope: "dependencies".into(),
            })
            .collect::<Vec<_>>();
        SbomScanReport {
            target: "/repo/demo".into(),
            manifests_scanned: 1,
            lockfiles: vec![SbomLockfile {
                path: "Cargo.lock".into(),
                sha256: "abc".into(),
            }],
            dependencies: Vec::new(),
            by_ecosystem: BTreeMap::from([("cargo".into(), components.len())]),
            components,
        }
    }
}
