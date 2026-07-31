//! The full risk-worklist deck: ranked rows with per-ranker citations, the
//! degraded banner, the contributor legend, and the unranked footer. Line-based
//! (the page is not frame-rendered), so plain/non-TTY output inherits it.

use crate::theme;
use crate::ui_view_models::{LegendEntry, WorklistRowModel, WorklistViewModel};
use ratatui::prelude::{Line, Span};

pub(super) fn worklist_lines(width: usize, model: &WorklistViewModel) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return crate::renderer::empty_state_panel(
            "no risk worklist",
            &[hint],
            &[
                ("context:build", "map the attack surface"),
                ("worklist:rank", "rank the highest-risk files"),
            ],
        );
    }
    let mut lines = vec![count_line(model)];
    append_degraded_banner(&mut lines, model);
    for row in &model.rows {
        lines.push(row_line(width, row));
    }
    append_legend(&mut lines, width, model);
    append_unranked_footer(&mut lines, model);
    lines
}

fn count_line(model: &WorklistViewModel) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!("RISK WORKLIST · {} file(s) ranked", model.rows.len()),
        theme::accent(),
    )])
}

fn append_degraded_banner(lines: &mut Vec<Line<'static>>, model: &WorklistViewModel) {
    for reason in &model.degraded {
        lines.push(Line::from(vec![Span::styled(
            format!("⚠ degraded — {reason}"),
            theme::warn(),
        )]));
    }
}

fn row_line(width: usize, row: &WorklistRowModel) -> Line<'static> {
    let text = format!(
        "#{}  {}   {}   {}",
        row.rank, row.glyphs, row.location, row.summary
    );
    Line::from(Span::raw(fit(&text, width)))
}

fn append_legend(lines: &mut Vec<Line<'static>>, width: usize, model: &WorklistViewModel) {
    if model.legend.is_empty() {
        return;
    }
    lines.push(Line::from(vec![Span::styled(
        "CONTRIBUTORS",
        theme::heading(),
    )]));
    for entry in &model.legend {
        lines.push(legend_line(width, entry));
    }
}

fn legend_line(width: usize, entry: &LegendEntry) -> Line<'static> {
    let text = match &entry.state_word {
        Some(word) => format!("  {} {} — {}", entry.glyph, entry.label, word),
        None => format!("  {} {}", entry.glyph, entry.label),
    };
    let style = if entry.dim {
        theme::muted()
    } else {
        theme::subtle()
    };
    Line::from(vec![Span::styled(fit(&text, width), style)])
}

fn append_unranked_footer(lines: &mut Vec<Line<'static>>, model: &WorklistViewModel) {
    if model.unranked_count == 0 {
        return;
    }
    lines.push(Line::from(vec![Span::styled(
        format!("{} files unranked (no signal)", model.unranked_count),
        theme::muted(),
    )]));
}

fn fit(value: &str, width: usize) -> String {
    crate::renderer::shared::text::fit(value, width)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    fn joined(lines: &[Line<'static>]) -> String {
        lines.iter().map(line_text).collect::<Vec<_>>().join("\n")
    }

    fn row(rank: usize, glyphs: &str, location: &str, summary: &str) -> WorklistRowModel {
        WorklistRowModel {
            rank,
            glyphs: glyphs.to_string(),
            location: location.to_string(),
            summary: summary.to_string(),
        }
    }

    fn legend(glyph: char, label: &str, state_word: Option<&str>, dim: bool) -> LegendEntry {
        LegendEntry {
            glyph,
            label: label.to_string(),
            state_word: state_word.map(str::to_string),
            dim,
        }
    }

    #[test]
    fn rows_show_glyph_and_raw_citations() {
        let model = WorklistViewModel {
            rows: vec![row(1, "AC", "src/a.rs:4", "A 92/100  C scan sink-gap")],
            legend: vec![legend('A', "attack surface", None, false)],
            degraded: vec![],
            unranked_count: 0,
            ranked_total: 1,
            empty_hint: None,
        };

        let text = joined(&worklist_lines(120, &model));

        assert!(text.contains("#1"), "{text}");
        assert!(text.contains("92/100"), "{text}");
        assert!(text.contains("src/a.rs:4"), "{text}");
    }

    #[test]
    fn degraded_banner_and_dim_legend_survive_style_stripping() {
        let model = WorklistViewModel {
            rows: vec![row(1, "A", "src/a.rs", "A 90/100")],
            legend: vec![legend('F', "call-graph fan-in", Some("no cpg graph"), true)],
            degraded: vec!["no cpg graph".to_string()],
            unranked_count: 2,
            ranked_total: 1,
            empty_hint: None,
        };

        let text = joined(&worklist_lines(120, &model));

        assert!(text.contains("⚠ degraded — no cpg graph"), "{text}");
        assert!(text.contains("call-graph fan-in — no cpg graph"), "{text}");
        assert!(text.contains("2 files unranked (no signal)"), "{text}");
    }

    #[test]
    fn empty_worklist_is_one_guidance_panel_not_dummy_rows() {
        let model = WorklistViewModel {
            empty_hint: Some("no worklist yet — run `context:build`".to_string()),
            ..Default::default()
        };

        let text = joined(&worklist_lines(120, &model));

        assert!(text.contains("context:build"), "{text}");
        assert!(text.contains("worklist:rank"), "{text}");
        assert!(!text.contains("#1"), "no fabricated rows: {text}");
    }

    #[test]
    fn glyph_rows_differ_in_stripped_text() {
        let a_row = joined(&[row_line(120, &row(1, "A", "src/a.rs", "A 90/100"))]);
        let f_row = joined(&[row_line(120, &row(1, "F", "src/a.rs", "F 12"))]);

        assert_ne!(a_row, f_row);
        assert!(a_row.contains('A'));
        assert!(f_row.contains('F'));
    }
}
