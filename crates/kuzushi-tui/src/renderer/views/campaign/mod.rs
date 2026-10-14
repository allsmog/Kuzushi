use super::*;
pub(in crate::renderer) use super::*;

mod batch_occurrence_lines;
mod batch_scan_config_lines;
mod campaign_lines;
mod context_study_lines;
mod coverage_lines;
mod reader;
mod summary;
pub(crate) use campaign_lines::campaign_lines;
pub(crate) use coverage_lines::{coverage_lines, coverage_page_rows};
pub(crate) use reader::{
    campaign_reader_scroll, campaign_selection_scroll, campaign_view_lines, compact_campaign_reader,
};

fn push_deck_text(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: usize,
    style: ratatui::style::Style,
) {
    lines.extend(
        crate::renderer::shared::text::wrap_text(text.trim(), width.saturating_sub(4).max(1))
            .into_iter()
            .map(|line| Line::styled(format!("  {line}"), style)),
    );
}

#[cfg(test)]
mod text_tests {
    use super::*;

    #[test]
    fn wrapped_deck_text_retains_long_sparklines_and_qualifications() {
        let text = format!(
            "HISTORY recent fp {} · spend >= {} · 90 snapshot(s)",
            "▄".repeat(90),
            "▄".repeat(90)
        );
        for width in [40, 60, 80, 96, 120, 160] {
            let mut lines = Vec::new();
            push_deck_text(&mut lines, &text, width, theme::subtle());
            assert!(lines.iter().all(|line| line.width() <= width));
            let joined = lines
                .iter()
                .flat_map(|line| &line.spans)
                .map(|span| span.content.as_ref())
                .collect::<Vec<_>>()
                .join(" ");
            let joined = joined.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(joined.contains("HISTORY recent"));
            assert!(joined.contains("spend >="));
            assert!(joined.contains("90 snapshot(s)"));
            assert_eq!(joined.chars().filter(|ch| *ch == '▄').count(), 180);
        }
    }
}
