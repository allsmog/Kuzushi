//! Findings heatmap — a module × severity grid. Each cell is a little bar whose
//! width tracks the count and whose colour is the severity column, so the eye
//! lands on the hot modules immediately.

use super::*;
use crate::theme;
use crate::ui_view_models::{FindingsHeatmap, ModuleRisk};

const CELL_W: usize = 7;
const COMPACT_CELL_W: usize = 5;
const COLUMNS: [Sev; 5] = [Sev::Critical, Sev::High, Sev::Medium, Sev::Low, Sev::Info];

#[derive(Debug, Clone, Copy)]
struct HeatmapLayout {
    name_w: usize,
    cell_w: usize,
    compact: bool,
}

pub(crate) fn heatmap_lines(width: usize, model: &FindingsHeatmap) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return scene_empty_state_lines(
            "no heatmap data",
            hint,
            &[("scan", "populate findings by module and severity")],
        );
    }
    let layout = heatmap_layout(width);
    let mut lines = vec![header_row(layout), blank_grid_row(layout)];
    lines.extend(model.rows.iter().map(|row| data_row(row, model, layout)));
    lines.push(blank());
    lines.push(legend_row(layout));
    lines
}

fn heatmap_layout(width: usize) -> HeatmapLayout {
    let compact = width < 2 + 14 + COLUMNS.len() * CELL_W;
    let cell_w = if width < 27 {
        2
    } else if compact {
        COMPACT_CELL_W
    } else {
        CELL_W
    };
    let reserved = 2 + COLUMNS.len() * cell_w;
    let available = width.saturating_sub(reserved);
    let name_w = if compact {
        available.max(1)
    } else {
        available.clamp(14, 40)
    };
    HeatmapLayout {
        name_w,
        cell_w,
        compact,
    }
}

fn header_row(layout: HeatmapLayout) -> Line<'static> {
    let mut spans = vec![span(
        format!("  {}", fixed("module", layout.name_w)),
        theme::label(),
    )];
    for sev in COLUMNS {
        spans.push(span(fixed(sev.short(), layout.cell_w), sev.style()));
    }
    line(spans)
}

fn blank_grid_row(layout: HeatmapLayout) -> Line<'static> {
    let total = layout.name_w + layout.cell_w * COLUMNS.len();
    line(vec![span(
        format!("  {}", "─".repeat(total)),
        theme::subtle(),
    )])
}

fn data_row(row: &ModuleRisk, model: &FindingsHeatmap, layout: HeatmapLayout) -> Line<'static> {
    let selected = model
        .selected_module
        .as_ref()
        .map_or(false, |module| module == &row.module);
    let marker = if selected { "▸ " } else { "  " };
    let mut spans = vec![
        span(marker, selected_row_style(selected)),
        span(
            fixed(&row.module, layout.name_w),
            selected_row_style(selected),
        ),
    ];
    for (count, sev) in row.counts.iter().zip(COLUMNS) {
        spans.push(cell(*count, sev, layout.cell_w));
    }
    line(spans)
}

fn legend_row(layout: HeatmapLayout) -> Line<'static> {
    if layout.compact {
        return line(vec![
            span("  C/H/M/L/I  ", theme::label()),
            span("critical → info · · none", theme::muted()),
        ]);
    }
    line(vec![
        span("  legend  ", theme::label()),
        span(
            "bar width ∝ count · colour = severity column · · = none",
            theme::muted(),
        ),
    ])
}

fn selected_row_style(selected: bool) -> ratatui::style::Style {
    if selected {
        // The review row owns the screen's one primary selection band. The
        // synchronized heatmap row stays visible in no-color terminals with a
        // marker and accent foreground, without creating a second band.
        theme::accent()
    } else {
        theme::primary()
    }
}

fn cell(count: u32, sev: Sev, cell_w: usize) -> Span<'static> {
    if count == 0 {
        return span(fixed("·", cell_w), theme::subtle());
    }
    // Keep `blocks + label` within CELL_W: a 4-digit count would otherwise make
    // the cell 8 wide and `fixed` would truncate it to a misleading number
    // (e.g. 1000 → "100"). Cap the readout at "999+" with one fewer block.
    let max_blocks = cell_w.saturating_sub(1).min(4);
    let (block_count, label) = if cell_w <= 2 && count > 9 {
        (1, "+".to_string())
    } else if count > 999 && cell_w >= CELL_W {
        (3, "999+".to_string())
    } else {
        ((count as usize).min(max_blocks), count.to_string())
    };
    let blocks = "█".repeat(block_count);
    span(fixed(&format!("{blocks}{label}"), cell_w), sev.style())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_layout_keeps_every_column_on_one_row() {
        let model = FindingsHeatmap {
            rows: vec![ModuleRisk {
                module: "(root)".to_string(),
                counts: [0, 3, 3, 1, 0],
                score: 0.0,
            }],
            selected_module: None,
            empty_hint: None,
        };

        let lines = heatmap_lines(38, &model);
        for line in &lines {
            assert!(line.width() <= 38, "heatmap row width {}", line.width());
        }
        let text = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        for label in ["CRIT", "HIGH", "MED", "LOW", "INFO"] {
            assert!(text.contains(label), "{text}");
        }
        assert!(text.contains("C/H/M/L/I"), "{text}");
    }
}
