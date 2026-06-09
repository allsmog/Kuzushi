//! The gallery's 2D diagrams — pure presentation that turns dummy security data
//! into styled box-drawing `Line`s. Each module owns one diagram; this file
//! holds the small shared vocabulary (severity tones, span/line helpers).

mod attack_path;
mod heatmap;

pub(super) use attack_path::attack_path_lines;
pub(super) use heatmap::heatmap_lines;

use crate::theme;
use ratatui::prelude::{Line, Span};
use ratatui::style::Style;

/// Severity tones shared across every diagram, mapped to the TUI theme palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sev {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Sev {
    pub(super) fn style(self) -> Style {
        match self {
            Sev::Critical => Style::default()
                .fg(theme::SEV_CRITICAL)
                .add_modifier(ratatui::style::Modifier::BOLD),
            Sev::High => Style::default().fg(theme::SEV_HIGH),
            Sev::Medium => Style::default().fg(theme::SEV_MEDIUM),
            Sev::Low => Style::default().fg(theme::SEV_LOW),
            Sev::Info => Style::default().fg(theme::T_LABEL),
        }
    }

    /// Short column header (fits a narrow heatmap cell).
    pub(super) fn short(self) -> &'static str {
        match self {
            Sev::Critical => "CRIT",
            Sev::High => "HIGH",
            Sev::Medium => "MED",
            Sev::Low => "LOW",
            Sev::Info => "INFO",
        }
    }
}

pub(super) fn span(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(text.into(), style)
}

pub(super) fn line(spans: Vec<Span<'static>>) -> Line<'static> {
    Line::from(spans)
}

pub(super) fn blank() -> Line<'static> {
    Line::from(String::new())
}

/// Centre `text` within `width` columns (truncating if it's too long).
pub(super) fn centered(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() >= width {
        return chars.into_iter().take(width).collect();
    }
    let pad = width - chars.len();
    let left = pad / 2;
    let right = pad - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

/// Left-pad/truncate `text` to exactly `width` columns.
pub(super) fn fixed(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() >= width {
        return chars.into_iter().take(width).collect();
    }
    format!("{}{}", text, " ".repeat(width - chars.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sample_taint() -> crate::ui_view_models::TaintFlowPath {
        use crate::ui_view_models::{TaintFlowPath, TaintStageModel};
        TaintFlowPath {
            cwe: "CWE-89".into(),
            severity: "critical".into(),
            stages: vec![
                TaintStageModel {
                    title: "req.body.id".into(),
                    location: "order.ts:12".into(),
                },
                TaintStageModel {
                    title: "buildQuery".into(),
                    location: "order.ts:42".into(),
                },
                TaintStageModel {
                    title: "db.exec()".into(),
                    location: "db.ts:7".into(),
                },
            ],
            empty_hint: None,
        }
    }

    fn sample_heatmap() -> crate::ui_view_models::FindingsHeatmap {
        use crate::ui_view_models::{FindingsHeatmap, ModuleRisk};
        FindingsHeatmap {
            rows: vec![
                ModuleRisk {
                    module: "auth".into(),
                    counts: [4, 3, 1, 0, 0],
                    score: 57.0,
                },
                ModuleRisk {
                    module: "api".into(),
                    counts: [2, 3, 4, 1, 0],
                    score: 44.0,
                },
            ],
            empty_hint: None,
        }
    }

    #[test]
    fn diagrams_render_non_empty() {
        for w in [72usize, 100] {
            for (name, lines) in [
                ("attack_path", attack_path_lines(w, &sample_taint())),
                ("heatmap", heatmap_lines(w, &sample_heatmap())),
            ] {
                let text = as_text(&lines);
                let widest = text.lines().map(|l| l.chars().count()).max().unwrap_or(0);
                println!("\n=== {name} @{w} (widest {widest}) ===\n{text}");
                assert!(!text.trim().is_empty(), "{name} rendered empty");
                assert!(widest <= w, "{name} overflows {w} (widest {widest})");
            }
        }
    }

    #[test]
    fn heatmap_caps_huge_counts_without_overflowing_a_cell() {
        use crate::ui_view_models::{FindingsHeatmap, ModuleRisk};
        let model = FindingsHeatmap {
            rows: vec![ModuleRisk {
                module: "auth".into(),
                counts: [5000, 12, 1, 0, 0],
                score: 0.0,
            }],
            empty_hint: None,
        };
        let text = as_text(&heatmap_lines(72, &model));
        let widest = text.lines().map(|l| l.chars().count()).max().unwrap_or(0);
        assert!(widest <= 72, "heatmap overflowed (widest {widest})");
        assert!(text.contains("999+"), "huge count should be capped to 999+");
    }

    #[test]
    fn empty_models_render_a_hint() {
        use crate::ui_view_models::{FindingsHeatmap, TaintFlowPath};
        let taint = TaintFlowPath {
            empty_hint: Some("no taint flow".into()),
            ..Default::default()
        };
        let heatmap = FindingsHeatmap {
            rows: Vec::new(),
            empty_hint: Some("no findings".into()),
        };
        assert!(!attack_path_lines(72, &taint).is_empty());
        assert!(!heatmap_lines(72, &heatmap).is_empty());
    }
}
