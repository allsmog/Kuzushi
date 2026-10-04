//! Directed connectors for flows returning to an earlier trust zone or node.
use super::*;

pub(super) fn connector_left(
    buf: &mut Buffer,
    area: Rect,
    from: (u16, u16),
    to: (u16, u16),
    color: Color,
) {
    let ((fx, fy), (tx, ty)) = (from, to);
    if fx <= tx.saturating_add(1) {
        return;
    }
    let tip = tx + 1;
    if fy == ty {
        hrun(buf, area, fy, tip + 1, fx + 1, color);
    } else {
        left_bend(buf, area, from, to, tip, color);
    }
    put(buf, area, tip, ty, "◀", color);
}

fn left_bend(
    buf: &mut Buffer,
    area: Rect,
    from: (u16, u16),
    to: (u16, u16),
    tip: u16,
    color: Color,
) {
    let ((fx, fy), (tx, ty)) = (from, to);
    let middle = (fx + tx) / 2;
    let down = ty > fy;
    hrun(buf, area, fy, middle + 1, fx + 1, color);
    put(buf, area, middle, fy, if down { "╭" } else { "╰" }, color);
    vrun(buf, area, middle, fy.min(ty) + 1, fy.max(ty), color);
    put(buf, area, middle, ty, if down { "╯" } else { "╮" }, color);
    hrun(buf, area, ty, tip + 1, middle, color);
}

/// Nodes within one trust-zone lane share a center column.
pub(super) fn connector_up(buf: &mut Buffer, area: Rect, x: u16, from: u16, to: u16, color: Color) {
    if from <= to.saturating_add(1) {
        return;
    }
    let tip = to + 1;
    vrun(buf, area, x, tip + 1, from, color);
    put(buf, area, x, tip, "▲", color);
}
