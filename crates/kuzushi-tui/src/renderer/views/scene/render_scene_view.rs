//! Renders a `Scene` into a half-block truecolor framebuffer (two square pixels
//! per cell via `▀`) with text labels overlaid. The actual rasterization (z-
//! buffer, shading, fog, glow) is pure and lives in `scene3d::render`; this file
//! is just the ratatui glue: header, framebuffer→cells, label stamping.

use super::diagram::{DfdDiagram, TreeDiagram};
use super::gallery::gallery_header_lines;
use super::scene_color::to_color;
use super::*;
use crate::scene3d::{
    attack_surface_scene, brighten, default_palette, render_to_framebuffer, Camera, Projector,
    SceneLabel, VizPage, BACKGROUND,
};
use crate::ui_view_models::{attack_tree, dfd_model, risk_by_module};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::{Color, Style};
use ratatui::widgets::Paragraph;

const CAM_DISTANCE: f32 = 4.2;

/// Frame-level renderer for the frame-rendered gallery pages: the 3D terrain
/// (half-block framebuffer) and the two Canvas diagrams (DFD graph, attack
/// tree). The line-based pages never reach here.
pub(crate) fn render_scene_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(gallery_header_lines(app)), outer[0]);
    match app.scene_page {
        VizPage::Dfd => frame.render_widget(DfdDiagram { model: dfd_model(app) }, outer[1]),
        VizPage::ExploitChain => {
            frame.render_widget(TreeDiagram { model: attack_tree(app) }, outer[1])
        }
        _ => render_terrain_body(frame, outer[1], app),
    }
}

// ── 3D terrain body: rasterize via scene3d, then overlay labels ────────────

fn render_terrain_body(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let (cols, rows) = (area.width as usize, area.height as usize);
    if cols == 0 || rows == 0 {
        return;
    }
    let scene = attack_surface_scene(&risk_by_module(&app.findings));
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
        yaw: app.scene_spin,
        pitch: app.scene_pitch,
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
        let fg = to_color(brighten(default_palette(lbl.color)));
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
    Span::styled(text, Style::default().fg(fg).bg(bg))
}
