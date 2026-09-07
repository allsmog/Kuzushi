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
use crate::ui_view_models::{attack_tree, cached_risk_by_module, dfd_model};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Paragraph, Wrap};

const CAM_DISTANCE: f32 = 4.2;

/// Frame-level renderer for the frame-rendered gallery pages: the 3D terrain
/// (half-block framebuffer) and the two Canvas diagrams (DFD graph, attack
/// tree). The line-based pages never reach here.
pub(crate) fn render_scene_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
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
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);
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
    if dfd_model(app).empty_hint.is_some()
        && crate::ui_view_models::map_local_artifacts_available(app)
    {
        frame.render_widget(
            Paragraph::new(super::gallery::local_inventory_summary_lines(
                app,
                area.width as usize,
            ))
            .wrap(Wrap { trim: false })
            .scroll((
                u16::try_from(app.router.scene().summary_scroll().max(0)).unwrap_or(u16::MAX),
                0,
            )),
            area,
        );
        return;
    }
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
    let model = crate::ui_view_models::entry_point_browser_model(app);
    if model.empty_hint.is_some() {
        frame.render_widget(
            EntryPointBrowser {
                model,
                selection: 0,
                detail_scroll: 0,
            },
            area,
        );
        return;
    }
    let selected = crate::ui_view_models::entry_point_browser_selection(app, &model);
    let (hint_area, body) = entry_point_browser_areas(area);
    frame.render_widget(
        Paragraph::new(entry_point_search_hint(
            app,
            model.entries.len(),
            model.counts.union,
        )),
        hint_area,
    );
    if let Some(selection) = selected {
        frame.render_widget(
            EntryPointBrowser {
                model,
                selection,
                detail_scroll: app.router.scene().entry_point_detail_scroll(),
            },
            body,
        );
    } else {
        frame.render_widget(
            Paragraph::new(
                "No visible selection. Change the search, clear it with C, or use the list keys.",
            ),
            body,
        );
    }
}

fn entry_point_search_hint(app: &ShellApp, visible: usize, total: usize) -> String {
    let editing = if app.router.scene().entry_point_searching() {
        "_ · Enter/Esc finish"
    } else {
        ""
    };
    format!(
        "/ search · C clear · {visible}/{total} · {}{editing}",
        app.router.scene().entry_point_query()
    )
}

fn entry_point_browser_areas(area: Rect) -> (Rect, Rect) {
    let hint = Rect {
        height: area.height.min(1),
        ..area
    };
    let body = Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    };
    (hint, body)
}

fn render_line_page_body(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    page: VizPage,
    line_scroll: u16,
) {
    frame.render_widget(
        Paragraph::new(page_body_lines(app, area, page))
            .wrap(Wrap { trim: false })
            .scroll((line_scroll, 0)),
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
