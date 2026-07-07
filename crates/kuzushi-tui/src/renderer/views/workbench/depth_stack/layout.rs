//! Depth-stack geometry. Guards keep every pane at or above its content budget:
//! the spine (fixed 11 cols) and drawer (fixed 7 rows) drop out under pressure
//! so the focal data-flow ladder never collapses below a usable size.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub(super) const SPINE_W: u16 = 11; // compressed findings spine width
pub(super) const DRAWER_H: u16 = 7; // tabbed triage/proof drawer height
pub(super) const PEEK_H: u16 = 6; // Depth-0 peek preview height
const LADDER_MIN_W: u16 = 24; // below this, drop the spine
const LADDER_MIN_H: u16 = 4; // below this, drop the drawer

pub(super) struct FrameSlots {
    pub context: Option<Rect>, // 1-row breadcrumb
    pub body: Rect,            // the active depth surface
    pub ops: Option<Rect>,     // operations bar (focus chip + map)
    pub keys: Option<Rect>,    // context-valid key rail
}

/// Split the depth-stack area into a breadcrumb / body / ops-bar / key-rail
/// stack. Below six rows there is no room for chrome, so the body takes it all.
/// The prompt is the shell's existing input line, drawn below this area.
pub(super) fn frame_slots(area: Rect) -> FrameSlots {
    if area.height < 6 {
        return FrameSlots {
            context: None,
            body: area,
            ops: None,
            keys: None,
        };
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);
    FrameSlots {
        context: Some(rows[0]),
        body: rows[1],
        ops: Some(rows[2]),
        keys: Some(rows[3]),
    }
}

pub(super) struct FindingSlots {
    pub spine: Option<Rect>,
    pub ladder: Rect,
    pub drawer: Option<Rect>,
}

/// Depth-1: `[ spine | ladder ]` over a full-width drawer.
pub(super) fn finding_slots(body: Rect) -> FindingSlots {
    let (upper, drawer) = split_bottom(body, DRAWER_H, LADDER_MIN_H);
    let (spine, ladder) = split_left(upper, SPINE_W, LADDER_MIN_W);
    FindingSlots {
        spine,
        ladder,
        drawer,
    }
}

/// Depth-0: worklist, with the peek preview borrowing the bottom rows.
pub(super) fn list_slots(body: Rect, peek: bool) -> (Rect, Option<Rect>) {
    if !peek {
        return (body, None);
    }
    split_bottom(body, PEEK_H, LADDER_MIN_H)
}

/// Reserve `bottom_h` rows at the base only if `min_top` rows survive above.
fn split_bottom(area: Rect, bottom_h: u16, min_top: u16) -> (Rect, Option<Rect>) {
    if area.height < bottom_h.saturating_add(min_top) {
        return (area, None);
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(bottom_h)])
        .split(area);
    (rows[0], Some(rows[1]))
}

/// Reserve `left_w` cols on the left only if `min_right` cols survive.
fn split_left(area: Rect, left_w: u16, min_right: u16) -> (Option<Rect>, Rect) {
    if area.width < left_w.saturating_add(min_right) {
        return (None, area);
    }
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(left_w), Constraint::Min(0)])
        .split(area);
    (Some(cols[0]), cols[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_layout_at_80x20_matches_the_spec_grid() {
        let slots = finding_slots(Rect::new(0, 0, 80, 20));
        let spine = slots.spine.expect("spine present on a wide body");
        let drawer = slots.drawer.expect("drawer present on a tall body");
        assert_eq!(spine.width, SPINE_W);
        assert_eq!(spine.height, 13); // 20 body − 7 drawer
        assert_eq!(slots.ladder.width, 80 - SPINE_W); // focal ladder takes the rest
        assert_eq!(drawer.height, DRAWER_H);
    }

    #[test]
    fn narrow_body_drops_the_spine_before_the_ladder() {
        let slots = finding_slots(Rect::new(0, 0, 30, 20));
        assert!(slots.spine.is_none());
        assert_eq!(slots.ladder.width, 30);
    }

    #[test]
    fn short_body_drops_the_drawer() {
        let slots = finding_slots(Rect::new(0, 0, 80, 9));
        assert!(slots.drawer.is_none());
    }

    #[test]
    fn peek_borrows_bottom_rows_only_when_room_exists() {
        let (list, peek) = list_slots(Rect::new(0, 0, 80, 20), true);
        assert_eq!(peek.expect("peek present").height, PEEK_H);
        assert_eq!(list.height, 20 - PEEK_H);
        let (_, none) = list_slots(Rect::new(0, 0, 80, 8), true);
        assert!(none.is_none());
    }
}
