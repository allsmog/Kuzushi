//! Screen-specific compositions for the Workbench.
//!
//! A `Composition` names the layout a screen chose — canvas with a contextual
//! drawer, a centered form, an operational dashboard — instead of packing
//! every page into the same uniform column split. Each variant owns its rect
//! solver and its small-terminal degradation, so the renderer and the mouse
//! hit-testing consume one geometry.

use super::PhaseSurfaceId;
use ratatui::layout::Rect;

/// Bottom drawers exist in two mockup variants: a compact strip that keeps
/// the workspace dominant, and an expanded card for a full recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrawerSize {
    Compact,
    Expanded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrawerSpec {
    pub(crate) surface: PhaseSurfaceId,
    pub(crate) size: DrawerSize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Composition {
    /// Legacy adaptive column split over the visible surfaces, in order.
    /// Pages keep this until their screen-specific composition lands.
    Columns(Vec<PhaseSurfaceId>),
    /// One dominant workspace surface with an optional contextual action
    /// drawer at the bottom (Map; Findings with a recommendation card).
    CanvasWithDrawer {
        canvas: PhaseSurfaceId,
        drawer: Option<DrawerSpec>,
    },
    /// One guided transaction form, horizontally centered (Scan configure,
    /// investigation configure).
    CenteredForm(PhaseSurfaceId),
    /// One status card sized to its ask: the centered-form width cap plus a
    /// height bound of the rows the card actually renders (Map readiness on a
    /// Map that still needs an action).
    StatusCard {
        surface: PhaseSurfaceId,
        content_rows: u16,
    },
    /// One question card demanding an operator decision (Clarify).
    QuestionCard(PhaseSurfaceId),
    /// Three-column operational dashboard with an optional log strip at the
    /// bottom (Run).
    OperationalColumns {
        left: PhaseSurfaceId,
        center: PhaseSurfaceId,
        right: PhaseSurfaceId,
        log_strip: Option<PhaseSurfaceId>,
    },
    /// Master list beside a reading detail, with an optional bottom drawer
    /// (Findings triage).
    ListDetail {
        list: PhaseSurfaceId,
        detail: PhaseSurfaceId,
        drawer: Option<DrawerSpec>,
    },
    /// One full-body reading surface with an optional action menu below it
    /// (single-finding triage with Choose-Next-Action).
    FocusDetail {
        body: PhaseSurfaceId,
        action_menu: Option<PhaseSurfaceId>,
    },
    /// The whole body given to one surface (Trace, Attack chain).
    FullScreen(PhaseSurfaceId),
    /// Plan, diff, and verification side by side (Patch).
    Triptych {
        plan: PhaseSurfaceId,
        diff: PhaseSurfaceId,
        verification: PhaseSurfaceId,
    },
}

/// Width below which every composition collapses to its primary surface.
const MIN_MULTI_REGION_COLUMNS: u16 = 78;
/// Height below which drawers, log strips, and action menus are dropped.
const MIN_AUXILIARY_ROWS: u16 = 10;
const COMPACT_DRAWER_ROWS: u16 = 6;
const EXPANDED_DRAWER_MAX_ROWS: u16 = 14;
const LOG_STRIP_ROWS: u16 = 4;
const ACTION_MENU_MAX_ROWS: u16 = 12;
pub(super) const CENTERED_FORM_MAX_COLUMNS: u16 = 100;

/// How a composition region should present itself: a canvas dominates the
/// workspace, a drawer is a contextual action card, a standard region keeps
/// the classic pane chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SurfaceRole {
    Standard,
    Canvas,
    Drawer,
}

impl Composition {
    /// The presentation role `surface` plays in this composition.
    pub(crate) fn role_of(&self, surface: PhaseSurfaceId) -> SurfaceRole {
        match self {
            Self::CanvasWithDrawer { canvas, drawer } => {
                if *canvas == surface {
                    SurfaceRole::Canvas
                } else if drawer.map(|spec| spec.surface) == Some(surface) {
                    SurfaceRole::Drawer
                } else {
                    SurfaceRole::Standard
                }
            }
            Self::ListDetail { drawer, .. } => {
                if drawer.map(|spec| spec.surface) == Some(surface) {
                    SurfaceRole::Drawer
                } else {
                    SurfaceRole::Standard
                }
            }
            Self::FocusDetail { body, action_menu } => {
                if *body == surface {
                    SurfaceRole::Canvas
                } else if *action_menu == Some(surface) {
                    SurfaceRole::Drawer
                } else {
                    SurfaceRole::Standard
                }
            }
            _ => SurfaceRole::Standard,
        }
    }

    /// Solve this composition into per-surface rects inside `area`, applying
    /// the small-terminal degradation rules: auxiliary regions (drawer, log
    /// strip, action menu) collapse first, then side regions, leaving the
    /// primary surface.
    pub(crate) fn solve(&self, area: Rect) -> Vec<(PhaseSurfaceId, Rect)> {
        if area.width == 0 || area.height == 0 {
            return Vec::new();
        }
        match self {
            Self::Columns(ids) => solve_columns(ids, area),
            Self::CanvasWithDrawer { canvas, drawer } => {
                solve_canvas_with_drawer(*canvas, *drawer, area)
            }
            Self::CenteredForm(id) => vec![(*id, centered_form_rect(area))],
            Self::StatusCard {
                surface,
                content_rows,
            } => vec![(*surface, status_card_rect(area, *content_rows))],
            Self::QuestionCard(id) => vec![(*id, centered_form_rect(area))],
            Self::OperationalColumns {
                left,
                center,
                right,
                log_strip,
            } => solve_operational(*left, *center, *right, *log_strip, area),
            Self::ListDetail {
                list,
                detail,
                drawer,
            } => solve_list_detail(*list, *detail, *drawer, area),
            Self::FocusDetail { body, action_menu } => {
                solve_focus_detail(*body, *action_menu, area)
            }
            Self::FullScreen(id) => vec![(*id, area)],
            Self::Triptych {
                plan,
                diff,
                verification,
            } => solve_triptych(*plan, *diff, *verification, area),
        }
    }
}

fn solve_columns(ids: &[PhaseSurfaceId], area: Rect) -> Vec<(PhaseSurfaceId, Rect)> {
    let rects = match ids.len() {
        0 => Vec::new(),
        1 => vec![area],
        2 => split_columns(area, &[44, 56]),
        _ => split_columns(area, &[40, 30, 30]),
    };
    ids.iter().copied().zip(rects).collect()
}

fn solve_canvas_with_drawer(
    canvas: PhaseSurfaceId,
    drawer: Option<DrawerSpec>,
    area: Rect,
) -> Vec<(PhaseSurfaceId, Rect)> {
    let Some(drawer) = drawer.filter(|_| area.height >= MIN_AUXILIARY_ROWS) else {
        return vec![(canvas, area)];
    };
    let drawer_rows = match drawer.size {
        DrawerSize::Compact => COMPACT_DRAWER_ROWS,
        DrawerSize::Expanded => (area.height / 2).min(EXPANDED_DRAWER_MAX_ROWS),
    }
    .min(area.height.saturating_sub(4));
    let (top, bottom) = split_rows_bottom(area, drawer_rows);
    vec![(canvas, top), (drawer.surface, bottom)]
}

fn solve_operational(
    left: PhaseSurfaceId,
    center: PhaseSurfaceId,
    right: PhaseSurfaceId,
    log_strip: Option<PhaseSurfaceId>,
    area: Rect,
) -> Vec<(PhaseSurfaceId, Rect)> {
    if area.width < MIN_MULTI_REGION_COLUMNS {
        return vec![(center, area)];
    }
    let (main, strip) =
        match log_strip.filter(|_| area.height >= MIN_AUXILIARY_ROWS + LOG_STRIP_ROWS) {
            Some(surface) => {
                let (top, bottom) = split_rows_bottom(area, LOG_STRIP_ROWS);
                (top, Some((surface, bottom)))
            }
            None => (area, None),
        };
    let columns = split_columns(main, &[26, 44, 30]);
    let mut regions = vec![
        (left, columns[0]),
        (center, columns[1]),
        (right, columns[2]),
    ];
    regions.extend(strip);
    regions
}

fn solve_list_detail(
    list: PhaseSurfaceId,
    detail: PhaseSurfaceId,
    drawer: Option<DrawerSpec>,
    area: Rect,
) -> Vec<(PhaseSurfaceId, Rect)> {
    if area.width < MIN_MULTI_REGION_COLUMNS {
        return vec![(list, area)];
    }
    let (main, drawer_region) = match drawer.filter(|_| area.height >= MIN_AUXILIARY_ROWS) {
        Some(spec) => {
            let rows = match spec.size {
                DrawerSize::Compact => COMPACT_DRAWER_ROWS,
                DrawerSize::Expanded => (area.height / 2).min(EXPANDED_DRAWER_MAX_ROWS),
            }
            .min(area.height.saturating_sub(4));
            let (top, bottom) = split_rows_bottom(area, rows);
            (top, Some((spec.surface, bottom)))
        }
        None => (area, None),
    };
    let columns = split_columns(main, &[38, 62]);
    let mut regions = vec![(list, columns[0]), (detail, columns[1])];
    regions.extend(drawer_region);
    regions
}

fn solve_focus_detail(
    body: PhaseSurfaceId,
    action_menu: Option<PhaseSurfaceId>,
    area: Rect,
) -> Vec<(PhaseSurfaceId, Rect)> {
    let Some(menu) = action_menu.filter(|_| area.height >= MIN_AUXILIARY_ROWS) else {
        return vec![(body, area)];
    };
    let menu_rows = (area.height / 3).min(ACTION_MENU_MAX_ROWS).max(4);
    let (top, bottom) = split_rows_bottom(area, menu_rows);
    vec![(body, top), (menu, bottom)]
}

fn solve_triptych(
    plan: PhaseSurfaceId,
    diff: PhaseSurfaceId,
    verification: PhaseSurfaceId,
    area: Rect,
) -> Vec<(PhaseSurfaceId, Rect)> {
    if area.width < MIN_MULTI_REGION_COLUMNS {
        return vec![(diff, area)];
    }
    if area.width < 120 {
        let columns = split_columns(area, &[38, 62]);
        return vec![(plan, columns[0]), (diff, columns[1])];
    }
    let columns = split_columns(area, &[28, 44, 28]);
    vec![
        (plan, columns[0]),
        (diff, columns[1]),
        (verification, columns[2]),
    ]
}

fn centered_form_rect(area: Rect) -> Rect {
    let width = area.width.min(CENTERED_FORM_MAX_COLUMNS);
    let x = area.x + (area.width - width) / 2;
    Rect::new(x, area.y, width, area.height)
}

/// A pane block spends its top row on its title, so a card that renders
/// `content_rows` lines occupies one row more than it writes.
const CARD_TITLE_ROWS: u16 = 1;

/// The card keeps the form's width cap and top edge but stops at its own last
/// row. Content taller than the body still takes the whole body — the pane
/// scrolls rather than dropping the rows it promised.
fn status_card_rect(area: Rect, content_rows: u16) -> Rect {
    let form = centered_form_rect(area);
    let height = content_rows
        .saturating_add(CARD_TITLE_ROWS)
        .min(form.height);
    Rect::new(form.x, form.y, form.width, height)
}

fn split_rows_bottom(area: Rect, bottom_rows: u16) -> (Rect, Rect) {
    let bottom_rows = bottom_rows.min(area.height);
    let top_rows = area.height - bottom_rows;
    (
        Rect::new(area.x, area.y, area.width, top_rows),
        Rect::new(area.x, area.y + top_rows, area.width, bottom_rows),
    )
}

pub(super) fn split_columns(area: Rect, percentages: &[u16]) -> Vec<Rect> {
    let mut x = area.x;
    percentages
        .iter()
        .enumerate()
        .map(|(index, percentage)| {
            let last = index + 1 == percentages.len();
            let width = if last {
                area.right().saturating_sub(x)
            } else {
                area.width.saturating_mul(*percentage) / 100
            };
            let rect = Rect::new(x, area.y, width, area.height);
            x = x.saturating_add(width);
            rect
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDE: Rect = Rect {
        x: 0,
        y: 0,
        width: 160,
        height: 40,
    };
    const NARROW: Rect = Rect {
        x: 0,
        y: 0,
        width: 50,
        height: 12,
    };

    fn ids(regions: &[(PhaseSurfaceId, Rect)]) -> Vec<PhaseSurfaceId> {
        regions.iter().map(|(id, _)| *id).collect()
    }

    fn regions_are_disjoint(regions: &[(PhaseSurfaceId, Rect)]) -> bool {
        for (index, (_, a)) in regions.iter().enumerate() {
            for (_, b) in regions.iter().skip(index + 1) {
                let overlap_x = a.x < b.right() && b.x < a.right();
                let overlap_y = a.y < b.bottom() && b.y < a.bottom();
                if overlap_x && overlap_y {
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn canvas_with_drawer_gives_the_canvas_the_dominant_region() {
        let composition = Composition::CanvasWithDrawer {
            canvas: PhaseSurfaceId::MapDfd,
            drawer: Some(DrawerSpec {
                surface: PhaseSurfaceId::MapReadiness,
                size: DrawerSize::Expanded,
            }),
        };
        let regions = composition.solve(WIDE);
        assert_eq!(
            ids(&regions),
            vec![PhaseSurfaceId::MapDfd, PhaseSurfaceId::MapReadiness]
        );
        assert!(regions[0].1.height > regions[1].1.height);
        assert!(regions_are_disjoint(&regions));
    }

    #[test]
    fn drawers_and_strips_collapse_first_on_small_terminals() {
        let with_drawer = Composition::CanvasWithDrawer {
            canvas: PhaseSurfaceId::MapDfd,
            drawer: Some(DrawerSpec {
                surface: PhaseSurfaceId::MapReadiness,
                size: DrawerSize::Compact,
            }),
        };
        let short = Rect::new(0, 0, 120, 8);
        assert_eq!(ids(&with_drawer.solve(short)), vec![PhaseSurfaceId::MapDfd]);

        let dashboard = Composition::OperationalColumns {
            left: PhaseSurfaceId::ScanScope,
            center: PhaseSurfaceId::ScanEngines,
            right: PhaseSurfaceId::ScanDelta,
            log_strip: Some(PhaseSurfaceId::ScanReceipt),
        };
        let regions = dashboard.solve(Rect::new(0, 0, 120, 12));
        assert!(!ids(&regions).contains(&PhaseSurfaceId::ScanReceipt));
    }

    #[test]
    fn operational_columns_degrade_to_the_center_surface() {
        let dashboard = Composition::OperationalColumns {
            left: PhaseSurfaceId::ScanScope,
            center: PhaseSurfaceId::ScanEngines,
            right: PhaseSurfaceId::ScanDelta,
            log_strip: None,
        };
        assert_eq!(
            ids(&dashboard.solve(NARROW)),
            vec![PhaseSurfaceId::ScanEngines]
        );
        let wide = dashboard.solve(WIDE);
        assert_eq!(wide.len(), 3);
        assert!(regions_are_disjoint(&wide));
    }

    #[test]
    fn status_card_keeps_the_form_width_cap_and_stops_at_its_last_row() {
        let card = Composition::StatusCard {
            surface: PhaseSurfaceId::MapReadiness,
            content_rows: 9,
        };
        let regions = card.solve(WIDE);
        assert_eq!(ids(&regions), vec![PhaseSurfaceId::MapReadiness]);
        let rect = regions[0].1;
        assert_eq!(rect.width, CENTERED_FORM_MAX_COLUMNS);
        assert_eq!(rect.y, WIDE.y, "the card stays at the top of the body");
        assert_eq!(rect.height, 10, "nine rows plus the pane title");
    }

    #[test]
    fn status_card_taller_than_the_body_keeps_the_body_and_scrolls() {
        let card = Composition::StatusCard {
            surface: PhaseSurfaceId::MapReadiness,
            content_rows: 40,
        };
        let short = Rect::new(0, 0, 60, 12);
        assert_eq!(card.solve(short)[0].1.height, short.height);
    }

    #[test]
    fn list_detail_keeps_the_list_when_degraded_and_supports_a_drawer() {
        let triage = Composition::ListDetail {
            list: PhaseSurfaceId::ReviewQueue,
            detail: PhaseSurfaceId::ReviewDetail,
            drawer: Some(DrawerSpec {
                surface: PhaseSurfaceId::ScanDelta,
                size: DrawerSize::Compact,
            }),
        };
        assert_eq!(
            ids(&triage.solve(NARROW)),
            vec![PhaseSurfaceId::ReviewQueue]
        );
        let wide = triage.solve(WIDE);
        assert_eq!(
            ids(&wide),
            vec![
                PhaseSurfaceId::ReviewQueue,
                PhaseSurfaceId::ReviewDetail,
                PhaseSurfaceId::ScanDelta
            ]
        );
        assert!(regions_are_disjoint(&wide));
    }

    #[test]
    fn centered_form_clamps_width_and_stays_inside_the_area() {
        let form = Composition::CenteredForm(PhaseSurfaceId::ScanScope);
        let regions = form.solve(WIDE);
        let rect = regions[0].1;
        assert!(rect.width <= 100);
        assert!(rect.right() <= WIDE.right());
        assert_eq!(ids(&form.solve(NARROW)), vec![PhaseSurfaceId::ScanScope]);
    }

    #[test]
    fn triptych_sheds_the_verification_column_before_the_plan() {
        let patch = Composition::Triptych {
            plan: PhaseSurfaceId::FixRemediation,
            diff: PhaseSurfaceId::FixCandidate,
            verification: PhaseSurfaceId::ProveReceipt,
        };
        let mid = patch.solve(Rect::new(0, 0, 100, 30));
        assert_eq!(
            ids(&mid),
            vec![PhaseSurfaceId::FixRemediation, PhaseSurfaceId::FixCandidate]
        );
        assert_eq!(
            ids(&patch.solve(NARROW)),
            vec![PhaseSurfaceId::FixCandidate]
        );
        assert_eq!(patch.solve(WIDE).len(), 3);
    }

    #[test]
    fn columns_variant_matches_the_legacy_split_ratios() {
        let composition = Composition::Columns(vec![
            PhaseSurfaceId::FixRemediation,
            PhaseSurfaceId::FixCandidate,
        ]);
        let regions = composition.solve(WIDE);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].1.width, 160 * 44 / 100);
        assert!(regions_are_disjoint(&regions));
    }
}
