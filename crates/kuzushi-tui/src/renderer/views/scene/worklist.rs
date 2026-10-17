//! The full risk-worklist deck: ranked rows with per-ranker citations, the
//! degraded banner, the contributor legend, and the unranked footer. Line-based
//! (the page is not frame-rendered), so plain/non-TTY output inherits it.

use super::line_page::LinePageRows;
use crate::theme;
use crate::ui_view_models::{LegendEntry, WorklistRowModel, WorklistViewModel};
use ratatui::prelude::{Line, Span};

/// The worklist as the rows it projects. Each ranked file, banner, and legend
/// entry is one row however many display lines its value wraps onto, so the
/// page's row total is the same at every canvas width.
pub(super) fn worklist_rows(width: usize, model: &WorklistViewModel) -> LinePageRows {
    LinePageRows::from_document_lines(worklist_document_lines(model), width)
}

fn worklist_document_lines(model: &WorklistViewModel) -> Vec<Line<'static>> {
    if let Some(message) = &model.history_notice {
        return crate::renderer::empty_state_panel(
            "saved ranking",
            &[message],
            &[
                ("runs", "inspect saved receipts"),
                ("run worklist:rank", "explicitly refresh advisory ranking"),
            ],
        );
    }
    if let Some(hint) = &model.empty_hint {
        let mut lines = crate::renderer::empty_state_panel(
            "no risk worklist",
            &[hint],
            &[
                ("run context:build", "prepare repository context"),
                ("run worklist:rank", "rank files from available evidence"),
            ],
        );
        append_degraded_banner(&mut lines, model);
        append_inspection(&mut lines, model);
        return lines;
    }
    let mut lines = vec![count_line(model)];
    lines.push(Line::from(
        "Advisory ranking from saved evidence; source freshness is unverified.",
    ));
    append_degraded_banner(&mut lines, model);
    for row in &model.rows {
        lines.push(row_line(row));
    }
    append_inspection(&mut lines, model);
    append_legend(&mut lines, model);
    append_unranked_footer(&mut lines, model);
    lines
}

fn count_line(model: &WorklistViewModel) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!(
            "RISK WORKLIST · {} of {} ranked files shown",
            model.rows.len(),
            model.ranked_total
        ),
        theme::accent(),
    )])
}

fn append_degraded_banner(lines: &mut Vec<Line<'static>>, model: &WorklistViewModel) {
    for reason in &model.degraded {
        lines.push(Line::from(vec![Span::styled(
            format!("⚠ degraded: {reason}"),
            theme::warn(),
        )]));
    }
}

fn append_inspection(lines: &mut Vec<Line<'static>>, model: &WorklistViewModel) {
    lines.extend(model.inspection.iter().cloned().map(Line::from));
}

fn row_line(row: &WorklistRowModel) -> Line<'static> {
    let text = format!(
        "#{}  {}   {}   {}",
        row.rank, row.glyphs, row.location, row.summary
    );
    Line::from(Span::raw(text))
}

fn append_legend(lines: &mut Vec<Line<'static>>, model: &WorklistViewModel) {
    if model.legend.is_empty() {
        return;
    }
    lines.push(Line::from(vec![Span::styled(
        "CONTRIBUTORS",
        theme::heading(),
    )]));
    for entry in &model.legend {
        lines.push(legend_line(entry));
    }
}

fn legend_line(entry: &LegendEntry) -> Line<'static> {
    let text = match &entry.state_word {
        Some(word) => format!("  {} {}: {}", entry.glyph, entry.label, word),
        None => format!("  {} {}", entry.glyph, entry.label),
    };
    let style = if entry.dim {
        theme::muted()
    } else {
        theme::subtle()
    };
    Line::from(vec![Span::styled(text, style)])
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

#[cfg(test)]
mod tests {
    use super::*;

    fn worklist_lines(width: usize, model: &WorklistViewModel) -> Vec<Line<'static>> {
        worklist_rows(width, model).into_lines()
    }

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
            inspection: Vec::new(),
            history_notice: None,
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
            inspection: Vec::new(),
            history_notice: None,
            unranked_count: 2,
            ranked_total: 1,
            empty_hint: None,
        };

        let text = joined(&worklist_lines(120, &model));

        assert!(text.contains("⚠ degraded: no cpg graph"), "{text}");
        assert!(text.contains("call-graph fan-in: no cpg graph"), "{text}");
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
        let a_row = joined(&[row_line(&row(1, "A", "src/a.rs", "A 90/100"))]);
        let f_row = joined(&[row_line(&row(1, "F", "src/a.rs", "F 12"))]);

        assert_ne!(a_row, f_row);
        assert!(a_row.contains('A'));
        assert!(f_row.contains('F'));
    }

    #[test]
    fn narrow_reading_preserves_the_full_path_evidence_and_population() {
        let path = "services/owned component/very-long-name/src/transport/settings.rs:128";
        let evidence = "A 92/100 C scan coverage missing for selected component";
        let model = WorklistViewModel {
            rows: vec![row(1, "AC", path, evidence)],
            ranked_total: 18,
            ..Default::default()
        };
        for width in [40, 60, 80, 120, 160] {
            let lines = worklist_lines(width, &model);
            assert!(lines.iter().all(|line| line.width() <= width));
            let text = lines.iter().map(line_text).collect::<String>();
            assert!(text.contains(path), "{width}: {text}");
            assert!(text.contains(evidence), "{width}: {text}");
            assert!(text.contains("1 of 18 ranked files shown"), "{text}");
            assert!(text.contains("source freshness is unverified"));
        }
    }

    #[test]
    fn an_empty_degraded_result_keeps_its_failure_reason_visible() {
        let model = WorklistViewModel {
            empty_hint: Some("No ranking evidence".into()),
            degraded: vec!["Coverage schema unavailable; explicit repair required".into()],
            inspection: Vec::new(),
            history_notice: None,
            ..Default::default()
        };
        let text = worklist_lines(40, &model)
            .iter()
            .map(line_text)
            .collect::<String>();
        assert!(text.contains("Coverage schema unavailable; explicit repair required"));
        assert!(text.contains("run worklist:rank"));
    }

    /// The defect #329 fixed for the component tree, guarded here for the
    /// worklist: its values wrap to the canvas, so a total counted in display
    /// lines would change with the terminal width. Every ranked file stays
    /// one row at every width.
    #[test]
    fn the_row_count_is_the_same_at_every_width() {
        let model = WorklistViewModel {
            rows: (1..=12)
                .map(|rank| {
                    row(
                        rank,
                        "AC",
                        &format!("services/owned component/very-long-name/src/file_{rank}.rs:12"),
                        "A 92/100 C scan coverage missing for selected component",
                    )
                })
                .collect(),
            legend: vec![legend('F', "call-graph fan-in", Some("no cpg graph"), true)],
            degraded: vec!["Coverage schema unavailable; explicit repair required".into()],
            inspection: Vec::new(),
            history_notice: None,
            unranked_count: 3,
            ranked_total: 40,
            empty_hint: None,
        };

        let totals = [40, 60, 80, 120, 200].map(|width| worklist_rows(width, &model).len());
        let display_lines = [40, 200].map(|width| worklist_rows(width, &model).into_lines().len());

        assert!(
            totals.windows(2).all(|pair| pair[0] == pair[1]),
            "{totals:?}"
        );
        assert!(
            display_lines[0] > display_lines[1],
            "fixture must wrap at 40 columns: {display_lines:?}"
        );
    }
    #[test]
    fn deep_inspection_limits_wrap_after_ranked_files_and_survive_narrow_reading() {
        let model = WorklistViewModel {
            rows: vec![row(1, "S", "owned.c:1", "S 12 raw points")],
            ranked_total: 1,
            inspection: vec![
                "Deep inspection: partial · 3 files · 16.0 KiB known source read".into(),
                "Bounds: 2000 file attempts · 16.0 KiB per file · 16.0 MiB source total".into(),
            ],
            ..Default::default()
        };
        for width in [40, 60, 80, 96, 120, 160] {
            let lines = worklist_lines(width, &model);
            assert!(lines.iter().all(|line| line.width() <= width));
            let text = lines.iter().map(line_text).collect::<String>();
            assert!(text.contains("16.0 MiB"), "{text}");
            assert!(text.find("owned.c").unwrap() < text.find("Deep inspection").unwrap());
        }
    }
    #[test]
    fn saved_history_failure_shows_recovery_without_fabricating_empty_rank_counts() {
        let model = WorklistViewModel {
            history_notice: Some("Saved ranking result is malformed.".into()),
            ..Default::default()
        };
        let text = joined(&worklist_lines(120, &model));
        assert!(text.contains("saved ranking"));
        assert!(text.contains("inspect saved receipts"));
        assert!(!text.contains("0 of 0"));
        assert!(!text.contains("context:build"));
    }
}
