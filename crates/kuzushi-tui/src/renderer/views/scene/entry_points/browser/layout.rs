use super::super::fit;
use crate::renderer::shared::text::display_width;
use crate::ui_view_models::EntryPointBreakdown;
use ratatui::layout::Rect;

pub(super) struct BrowserLayout {
    pub(super) summary: Vec<String>,
    pub(super) summary_area: Rect,
    pub(super) list: Rect,
    pub(super) detail: Rect,
}

pub(super) fn browser_layout(area: Rect, model: &EntryPointBreakdown) -> BrowserLayout {
    let summary = if area.height < 9 {
        vec![fit(
            &format!(
                "{} extracted · {} {}",
                model.counts.extracted,
                model.receipt.warnings.len(),
                warning_label(model.receipt.warnings.len())
            ),
            area.width as usize,
        )]
    } else {
        compact_summary(area.width as usize, model)
    };
    let summary_height = (summary.len() as u16).min(area.height);
    let summary_area = Rect {
        height: summary_height,
        ..area
    };
    let body = Rect {
        y: area.y + summary_height,
        height: area.height - summary_height,
        ..area
    };
    let (list, detail) = pane_areas(body);
    BrowserLayout {
        summary,
        summary_area,
        list,
        detail,
    }
}

fn compact_summary(width: usize, model: &EntryPointBreakdown) -> Vec<String> {
    let full = format!(
        "{} extracted · {} modeled · {} model only",
        model.counts.extracted, model.counts.modeled, model.counts.model_only
    );
    let short = format!(
        "{} extracted · {} model only",
        model.counts.extracted, model.counts.model_only
    );
    let counts = if display_width(&full) <= width {
        full
    } else {
        short
    };
    let warning_label = warning_label(model.receipt.warnings.len());
    let state = format!(
        "{} · {} {warning_label} · PgUp/PgDn detail",
        model.receipt.freshness.label(),
        model.receipt.warnings.len()
    );
    vec![fit(&counts, width), fit(&state, width)]
}

fn warning_label(count: usize) -> &'static str {
    if count == 1 {
        "warning"
    } else {
        "warnings"
    }
}

fn pane_areas(area: Rect) -> (Rect, Rect) {
    if area.width >= 90 && area.height >= 8 {
        let width = (area.width * 2 / 5).clamp(32, 60);
        return (
            Rect { width, ..area },
            Rect {
                x: area.x + width + 1,
                width: area.width.saturating_sub(width + 1),
                ..area
            },
        );
    }
    stacked_areas(area)
}

fn stacked_areas(area: Rect) -> (Rect, Rect) {
    let list_height = if area.height < 9 {
        area.height.min(1)
    } else {
        (area.height / 3).clamp(3, 8)
    };
    let gap = u16::from(area.height >= 9);
    let top = (list_height + gap).min(area.height);
    (
        Rect {
            height: list_height,
            ..area
        },
        Rect {
            y: area.y + top,
            height: area.height - top,
            ..area
        },
    )
}

pub(super) fn page_offset(requested: usize, direction: i32, visible: usize, total: usize) -> usize {
    let visible = visible.max(1);
    let end = total.saturating_sub(visible);
    let start = requested.min(end);
    if direction < 0 {
        start.saturating_sub(visible)
    } else {
        start.saturating_add(visible).min(end)
    }
}
