//! Crisp box-drawing diagrams painted straight into the ratatui `Buffer`:
//! rounded node boxes (`Block` rounded borders) joined by orthogonal connectors
//! built from solid box-drawing glyphs (`─ │ ╭ ╮ ╰ ╯`) with arrowheads. Unlike
//! the braille `Canvas`, these use full-cell strokes, so boxes and lines read
//! crisp instead of grainy. One glyph per cell; connectors route in right
//! angles between node anchors.

mod dfd;
mod tree;

pub(crate) use dfd::DfdDiagram;
pub(crate) use tree::TreeDiagram;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Widget, Wrap};

/// Set one cell's glyph + colour, clipped to `area` (coords are area-relative).
pub(super) fn put(buf: &mut Buffer, area: Rect, x: u16, y: u16, ch: &str, color: Color) {
    let (ax, ay) = (area.x + x, area.y + y);
    if ax < area.right() && ay < area.bottom() {
        if let Some(cell) = buf.cell_mut((ax, ay)) {
            cell.set_symbol(ch);
            let color = crate::theme::terminal_color(color);
            if color != Color::Reset {
                cell.set_fg(color);
            }
        }
    }
}

pub(super) fn diagram_primary() -> Color {
    if crate::theme::active_theme().high_contrast {
        crate::theme::T_HEADING
    } else {
        crate::theme::T_PRIMARY
    }
}

pub(super) fn diagram_muted() -> Color {
    if crate::theme::active_theme().high_contrast {
        crate::theme::T_PRIMARY
    } else {
        crate::theme::T_MUTED
    }
}

pub(super) fn diagram_subtle() -> Color {
    if crate::theme::active_theme().high_contrast {
        crate::theme::T_MUTED
    } else {
        crate::theme::T_SUBTLE
    }
}

pub(super) fn render_empty_state_panel(
    buf: &mut Buffer,
    area: Rect,
    glyph_label: &str,
    hint: &str,
    ctas: &[(&str, &str)],
) {
    Paragraph::new(crate::renderer::empty_state_panel(
        glyph_label,
        &[hint],
        ctas,
    ))
    .wrap(Wrap { trim: false })
    .render(area, buf);
}

/// Blank a rect (area-relative coords) so a box drawn after the connector
/// pass hides any edge run beneath its interior — edges route under boxes,
/// never through them.
pub(super) fn clear_rect(buf: &mut Buffer, area: Rect, x: u16, y: u16, w: u16, h: u16) {
    for row in y..y.saturating_add(h) {
        for col in x..x.saturating_add(w) {
            put(buf, area, col, row, " ", Color::Reset);
        }
    }
}

/// Write a label, truncated to fit within `area`.
pub(super) fn text(buf: &mut Buffer, area: Rect, x: u16, y: u16, s: &str, color: Color) {
    let (ax, ay) = (area.x + x, area.y + y);
    if ax >= area.right() || ay >= area.bottom() {
        return;
    }
    let max = (area.right() - ax) as usize;
    let clipped: String = s.chars().take(max).collect();
    buf.set_string(ax, ay, clipped, diagram_style(color));
}

/// A rounded node box with a left-aligned label on its middle row.
pub(super) fn boxed(
    buf: &mut Buffer,
    area: Rect,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    label: &str,
    border: Color,
    label_color: Color,
) {
    let rect = Rect {
        x: area.x + x,
        y: area.y + y,
        width: w,
        height: h,
    }
    .intersection(area);
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(diagram_style(border))
        .render(rect, buf);
    // Truncate to the box interior so long real labels don't spill past the border.
    let inner = (w.saturating_sub(3)) as usize;
    let clipped: String = label.chars().take(inner).collect();
    text(buf, area, x + 2, y + h / 2, &clipped, label_color);
}

/// A titled container panel (plain borders) — e.g. a DFD trust zone.
pub(super) fn panel(
    buf: &mut Buffer,
    area: Rect,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    title: &str,
    color: Color,
) {
    let rect = Rect {
        x: area.x + x,
        y: area.y + y,
        width: w,
        height: h,
    }
    .intersection(area);
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(diagram_style(color))
        .title(ratatui::text::Span::styled(
            format!(" {title} "),
            diagram_style(color),
        ))
        .render(rect, buf);
}

fn diagram_style(color: Color) -> Style {
    let color = crate::theme::terminal_color(color);
    if color == Color::Reset {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

/// Draw a horizontal glyph run on row `y` over `x0..x1`.
pub(super) fn hrun(buf: &mut Buffer, area: Rect, y: u16, x0: u16, x1: u16, color: Color) {
    for x in x0..x1 {
        put(buf, area, x, y, "─", color);
    }
}

/// Draw a vertical glyph run in column `x` over `y0..y1`.
pub(super) fn vrun(buf: &mut Buffer, area: Rect, x: u16, y0: u16, y1: u16, color: Color) {
    for y in y0..y1 {
        put(buf, area, x, y, "│", color);
    }
}

/// Orthogonal left→right connector (Z-route) with a `▶` arrowhead at `to`.
pub(super) fn connector_h(
    buf: &mut Buffer,
    area: Rect,
    from: (u16, u16),
    to: (u16, u16),
    color: Color,
) {
    let ((fx, fy), (tx, ty)) = (from, to);
    if tx <= fx.saturating_add(1) {
        return;
    }
    let tip = tx - 1;
    if fy == ty {
        hrun(buf, area, fy, fx, tip, color);
        put(buf, area, tip, fy, "▶", color);
        return;
    }
    connector_h_zroute(buf, area, (fx, fy), (tx, ty), tip, color);
}

/// The bent left→right route: out from `from`, down/up the midpoint column, then
/// into `to`. Corners pick rounded glyphs by direction.
fn connector_h_zroute(
    buf: &mut Buffer,
    area: Rect,
    from: (u16, u16),
    to: (u16, u16),
    tip: u16,
    color: Color,
) {
    let ((fx, fy), (tx, ty)) = (from, to);
    let mx = (fx + tx) / 2;
    let down = ty > fy;
    hrun(buf, area, fy, fx, mx, color);
    put(buf, area, mx, fy, if down { "╮" } else { "╯" }, color);
    let (y0, y1) = if down { (fy + 1, ty) } else { (ty + 1, fy) };
    vrun(buf, area, mx, y0, y1, color);
    put(buf, area, mx, ty, if down { "╰" } else { "╭" }, color);
    hrun(buf, area, ty, mx + 1, tip, color);
    put(buf, area, tip, ty, "▶", color);
}

/// Orthogonal top→down connector (Z-route) with a `▼` arrowhead at `to`.
pub(super) fn connector_v(
    buf: &mut Buffer,
    area: Rect,
    from: (u16, u16),
    to: (u16, u16),
    color: Color,
) {
    let ((fx, fy), (tx, ty)) = (from, to);
    if ty <= fy.saturating_add(1) {
        return;
    }
    let tip = ty - 1;
    if fx == tx {
        vrun(buf, area, fx, fy, tip, color);
        put(buf, area, fx, tip, "▼", color);
        return;
    }
    connector_v_zroute(buf, area, (fx, fy), (tx, ty), tip, color);
}

/// The bent top→down route: down from `from`, across the midpoint row, then down
/// into `to`. Corners pick rounded glyphs by direction.
fn connector_v_zroute(
    buf: &mut Buffer,
    area: Rect,
    from: (u16, u16),
    to: (u16, u16),
    tip: u16,
    color: Color,
) {
    let ((fx, fy), (tx, ty)) = (from, to);
    let my = (fy + ty) / 2;
    let right = tx > fx;
    vrun(buf, area, fx, fy, my, color);
    put(buf, area, fx, my, if right { "╰" } else { "╯" }, color);
    let (x0, x1) = if right { (fx + 1, tx) } else { (tx + 1, fx) };
    hrun(buf, area, my, x0, x1, color);
    put(buf, area, tx, my, if right { "╮" } else { "╭" }, color);
    vrun(buf, area, tx, my + 1, tip, color);
    put(buf, area, tx, tip, "▼", color);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{DfdFlowModel, DfdKind, DfdModel, DfdNodeModel};

    fn render_to_text(widget: impl Widget, w: u16, h: u16) -> String {
        let area = Rect::new(0, 0, w, h);
        let mut buf = Buffer::empty(area);
        widget.render(area, &mut buf);
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sample_dfd() -> DfdModel {
        DfdModel {
            zones: vec!["internet".into(), "app".into(), "data".into()],
            nodes: vec![
                sample_node("user", "internet", DfdKind::Entity),
                sample_node("api", "app", DfdKind::Process),
                sample_node("db", "data", DfdKind::Store),
            ],
            flows: vec![
                sample_flow("user", "api", "https", "tb-edge"),
                sample_flow("api", "db", "sql", "tb-data"),
            ],
            empty_hint: None,
            ..Default::default()
        }
    }

    fn sample_node(key: &str, zone: &str, kind: DfdKind) -> DfdNodeModel {
        DfdNodeModel {
            key: key.into(),
            name: key.into(),
            zone: zone.into(),
            kind,
        }
    }

    fn sample_flow(from: &str, to: &str, label: &str, boundary: &str) -> DfdFlowModel {
        DfdFlowModel {
            key: format!("{from}->{to}"),
            from_id: from.into(),
            to_id: to.into(),
            from: from.into(),
            to: to.into(),
            crosses: true,
            label: label.into(),
            boundary_ids: vec![boundary.into()],
        }
    }

    fn sample_tree() -> crate::ui_view_models::AttackTree {
        use crate::ui_view_models::{AttackChain, AttackTree};
        use crate::ChainSeverity;
        AttackTree {
            chains: vec![
                AttackChain {
                    title: "SQLi /orders".into(),
                    severity: ChainSeverity::Critical,
                    narrative: None,
                    impact_description: None,
                    preconditions: Vec::new(),
                    steps: vec!["unsanitised id".into(), "raw db.exec()".into()],
                    hidden_step_count: 0,
                },
                AttackChain {
                    title: "IDOR /account".into(),
                    severity: ChainSeverity::High,
                    narrative: None,
                    impact_description: None,
                    preconditions: Vec::new(),
                    steps: vec!["missing owner check".into()],
                    hidden_step_count: 0,
                },
            ],
            hidden_chain_count: 0,
            empty_hint: None,
        }
    }

    #[test]
    fn diagrams_render() {
        for w in [72u16, 100] {
            println!(
                "\n=== dfd @{w} ===\n{}",
                render_to_text(
                    DfdDiagram {
                        model: sample_dfd(),
                        selection: Some(0),
                        detail_scroll: 0,
                        focused: false,
                        context_selection: 0,
                    },
                    w,
                    24
                )
            );
            println!(
                "\n=== attack_tree @{w} ===\n{}",
                render_to_text(
                    TreeDiagram {
                        model: sample_tree()
                    },
                    w,
                    24
                )
            );
        }
    }

    #[test]
    fn empty_models_draw_a_hint_not_a_panic() {
        use crate::ui_view_models::{AttackTree, DfdModel};
        let dfd = DfdModel {
            empty_hint: Some("no threat model".into()),
            ..Default::default()
        };
        let tree = AttackTree {
            empty_hint: Some("no chains".into()),
            ..Default::default()
        };
        let _ = render_to_text(
            DfdDiagram {
                model: dfd,
                selection: None,
                detail_scroll: 0,
                focused: false,
                context_selection: 0,
            },
            72,
            24,
        );
        let _ = render_to_text(TreeDiagram { model: tree }, 72, 24);
    }
}
