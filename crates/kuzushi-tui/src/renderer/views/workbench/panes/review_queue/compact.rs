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
    disclose_hidden_filters(&mut summaries, budget, model.path_history);
    summaries
        .into_iter()
        .take(budget)
        .map(|text| Line::styled(fit(&text, width), theme::muted()))
        .collect()
}

fn disclose_hidden_filters(lines: &mut Vec<String>, budget: usize, path_history: bool) {
    if lines.len() <= budget || budget == 0 {
        return;
    }
    // Full filter chips and facet counts remain available in plain output.
    // Never imply that a clipped summary is the complete filter state.
    lines.truncate(budget);
    lines[budget - 1] = if path_history {
        "saved revisions · / inspect"
    } else {
        "filters active · / inspect"
    }
    .into();
}

fn card(row: &ReviewQueueRow, width: usize, height: usize, selected: bool) -> Vec<Line<'static>> {
    let source = if height < 3 {
        format!(" s{}", row.source_count)
    } else {
        String::new()
    };
    let titles = title_preview(&row.title, width, height.saturating_sub(2).clamp(1, 2));
    let mut lines = vec![card_header(row, &source, width, selected)];
    lines.extend(
        titles
            .iter()
            .map(|text| card_text(text, theme::heading(), width, selected)),
    );
    lines.push(card_decision_line(row, width, selected));
    lines.push(card_text(
        &card_location_or_occurrence(row, width),
        theme::muted(),
        width,
        selected,
    ));
    lines.truncate(height);
    lines
}

/// `F-0003 H unverified`: identity, severity and proof each in their own tone
/// so a critical finding stands out before its title is read.
fn card_header(row: &ReviewQueueRow, source: &str, width: usize, selected: bool) -> Line<'static> {
    let pointer = if selected { "▸" } else { " " };
    if selected {
        let text = format!(
            "{pointer}{} {} {}{source}",
            row.alias,
            severity_glyph(row.severity_tone),
            proof_label(row)
        );
        return card_text(&text, theme::primary(), width, true);
    }
    Line::from(vec![
        Span::styled(format!("{pointer}{} ", row.alias), theme::label()),
        Span::styled(
            severity_glyph(row.severity_tone).to_owned(),
            theme::severity_tone(row.severity_tone),
        ),
        Span::styled(
            format!(" {}", proof_label(row)),
            theme::proof_confidence_tone(row.proof_confidence),
        ),
        Span::styled(source.to_owned(), theme::muted()),
    ])
}

fn card_decision_line(row: &ReviewQueueRow, width: usize, selected: bool) -> Line<'static> {
    let meta = format!(
        "  sources:{} · {} · ",
        row.source_count,
        authority_marker(row)
    );
    let decision = review_queue_compact_decision(row);
    if selected {
        return card_text(&format!("{meta}{decision}"), theme::primary(), width, true);
    }
    Line::from(vec![
        Span::styled(fit(&meta, width), theme::muted()),
        Span::styled(decision.to_owned(), review_queue_decision_style(row)),
    ])
}

fn card_text(
    text: &str,
    style: ratatui::style::Style,
    width: usize,
    selected: bool,
) -> Line<'static> {
    Line::styled(fit(text, width), review_queue_row_style(style, selected))
}

fn proof_label(row: &ReviewQueueRow) -> &str {
    match row.proof_confidence {
        ProofConfidence::Confirmed => "runtime verified",
        ProofConfidence::Likely => "static evidence",
        ProofConfidence::Unverified => "unverified",
        ProofConfidence::Dismissed => row.proof_confidence_label.as_str(),
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
    format!(
        "  {}",
        fit_location_label(&row.location, width.saturating_sub(2))
    )
}
