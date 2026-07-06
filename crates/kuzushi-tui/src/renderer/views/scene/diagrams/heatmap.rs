//! Findings heatmap — a module × severity grid. Each cell is a little bar whose
//! width tracks the count and whose colour is the severity column, so the eye
//! lands on the hot modules immediately.

use super::*;
use crate::theme;
use crate::ui_view_models::{FindingsHeatmap, ModuleRisk};

const CELL_W: usize = 7;
const COLUMNS: [Sev; 5] = [Sev::Critical, Sev::High, Sev::Medium, Sev::Low, Sev::Info];

pub(crate) fn heatmap_lines(width: usize, model: &FindingsHeatmap) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return scene_empty_state_lines(
            "no heatmap data",
            hint,
            &[("scan", "populate findings by module and severity")],
        );
    }
    let name_w = heatmap_name_width(width);
    let mut lines = vec![header_row(name_w), blank_grid_row(name_w)];
    lines.extend(model.rows.iter().map(|row| data_row(row, model, name_w)));
    lines.push(blank());
    lines.push(line(vec![
        span("  legend  ", theme::label()),
        span(
            "bar width ∝ count · colour = severity column · · = none",
            theme::muted(),
        ),
    ]));
    lines
}

fn heatmap_name_width(width: usize) -> usize {
    width
        .saturating_sub(2 + COLUMNS.len() * CELL_W)
        .clamp(14, 40)
}

fn header_row(name_w: usize) -> Line<'static> {
    let mut spans = vec![span(
        format!("  {}", fixed("module", name_w)),
        theme::label(),
    )];
    for sev in COLUMNS {
        spans.push(span(fixed(sev.short(), CELL_W), sev.style()));
    }
    line(spans)
}

fn blank_grid_row(name_w: usize) -> Line<'static> {
    let total = name_w + CELL_W * COLUMNS.len();
    line(vec![span(
        format!("  {}", "─".repeat(total)),
        theme::subtle(),
    )])
}

fn data_row(row: &ModuleRisk, model: &FindingsHeatmap, name_w: usize) -> Line<'static> {
    let selected = model
        .selected_module
        .as_ref()
        .map_or(false, |module| module == &row.module);
    let marker = "  ";
    let mut spans = vec![
        span(marker, selected_row_style(selected)),
        span(fixed(&row.module, name_w), selected_row_style(selected)),
    ];
    for (count, sev) in row.counts.iter().zip(COLUMNS) {
        spans.push(cell(*count, sev));
    }
    line(spans)
}

fn selected_row_style(selected: bool) -> ratatui::style::Style {
    if selected {
        theme::selection()
    } else {
        theme::primary()
    }
}

fn cell(count: u32, sev: Sev) -> Span<'static> {
    if count == 0 {
        return span(fixed("·", CELL_W), theme::subtle());
    }
    // Keep `blocks + label` within CELL_W: a 4-digit count would otherwise make
    // the cell 8 wide and `fixed` would truncate it to a misleading number
    // (e.g. 1000 → "100"). Cap the readout at "999+" with one fewer block.
    let (block_count, label) = if count > 999 {
        (3, "999+".to_string())
    } else {
        ((count as usize).min(4), count.to_string())
    };
    let blocks = "█".repeat(block_count);
    span(fixed(&format!("{blocks}{label}"), CELL_W), sev.style())
}
