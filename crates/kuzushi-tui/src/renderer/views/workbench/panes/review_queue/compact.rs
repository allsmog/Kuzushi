//! Finding cards for the narrow queue beside a complete, scrollable claim.
use super::*;
use crate::renderer::shared::text::wrap_text;

pub(super) fn lines(model: &ReviewQueueModel, inner: Rect) -> Vec<Line<'static>> {
    let width = usize::from(inner.width);
    let height = usize::from(inner.height);
    let mut lines = chrome(model, width, height);
    let available = height.saturating_sub(lines.len());
    let card_height = available.clamp(1, 5);
    let count = available / card_height;
    let selected = model
        .selected_row
        .or_else(|| model.rows.iter().position(|row| row.selected));
    let start = viewport_start_for_cursor(model.rows.len(), count.max(1), selected.unwrap_or(0));
    for (index, row) in model.rows.iter().enumerate().skip(start).take(count) {
        lines.extend(card(row, width, card_height, selected == Some(index)));
    }
    lines
}

fn chrome(model: &ReviewQueueModel, width: usize, height: usize) -> Vec<Line<'static>> {
    let mut summaries = active_filter_lines(model, width);
    // Finding identity and title retain two rows even in a tiny viewport.
    let budget = height.saturating_sub(2);
    disclose_hidden_filters(&mut summaries, budget);
    summaries
        .into_iter()
        .take(budget)
        .map(|text| Line::styled(fit(&text, width), theme::muted()))
        .collect()
}

fn disclose_hidden_filters(lines: &mut Vec<String>, budget: usize) {
    if lines.len() <= budget || budget == 0 {
        return;
    }
    // Full filter chips and facet counts remain available in plain output.
    // Never imply that a clipped summary is the complete filter state.
    lines.truncate(budget);
    lines[budget - 1] = "filters active · / inspect".into();
}

fn card(row: &ReviewQueueRow, width: usize, height: usize, selected: bool) -> Vec<Line<'static>> {
    let style = review_queue_row_style(theme::primary(), selected);
    let pointer = if selected { "▸" } else { " " };
    let mut text = vec![format!(
        "{pointer}{} {} {}",
        row.alias,
        severity_glyph(row.severity_tone),
        proof_label(row)
    )];
    text.extend(title_preview(
        &row.title,
        width,
        height.saturating_sub(2).clamp(1, 2),
    ));
    text.push(format!(
        "  sources:{} · {} · {}",
        row.source_count,
        authority_marker(row),
        review_queue_compact_decision(row)
    ));
    text.push(card_location_or_occurrence(row, width));
    text.into_iter()
        .take(height)
        .map(|text| Line::styled(fit(&text, width), style))
        .collect()
}

fn proof_label(row: &ReviewQueueRow) -> &'static str {
    match row.proof_confidence {
        ProofConfidence::Confirmed => "runtime verified",
        ProofConfidence::Likely => "static evidence",
        ProofConfidence::Unverified => "unverified",
        ProofConfidence::Dismissed => "dismissed",
    }
}

fn title_preview(title: &str, width: usize, budget: usize) -> Vec<String> {
    let wrapped = wrap_text(title, width.saturating_sub(2));
    let overflow = wrapped.len() > budget;
    wrapped
        .into_iter()
        .take(budget)
        .enumerate()
        .map(|(index, text)| {
            let text = if overflow && index + 1 == budget {
                format!("{text} …")
            } else {
                text
            };
            format!("  {}", fit(&text, width.saturating_sub(2)))
        })
        .collect()
}

fn card_location_or_occurrence(row: &ReviewQueueRow, width: usize) -> String {
    if let Some(occurrence) = row.occurrence {
        return format!(
            "  occ {}/{} · p{} f{}",
            occurrence.seen, occurrence.completed, occurrence.planned, occurrence.failed
        );
    }
    format!("  {}", fit_path(&row.location, width.saturating_sub(2)))
}
