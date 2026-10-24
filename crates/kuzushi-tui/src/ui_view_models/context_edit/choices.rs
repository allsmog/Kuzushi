use super::*;
use crate::renderer::shared::text::fit;
use kuzushi_core::capabilities::threat_model::{ContextEditConstraint, ContextFieldChoice};
use ratatui::layout::Rect;

pub(crate) fn context_choice_area(draft: &ContextEditDraft, area: Rect, checkpoint: bool) -> Rect {
    let role = draft.entries[draft.cursor]
        .pointer
        .as_deref()
        .unwrap_or_default()
        .ends_with("/type");
    let width = area.width.min(if role && !draft.choice_details {
        44
    } else {
        80
    });
    let content = choice_content_rows(draft, width.saturating_sub(2) as usize);
    let overhead = 5 + u16::from(checkpoint);
    let height = area.height.min(content.saturating_add(overhead)).min(28);
    centered_card(area, width, height)
}

pub(crate) fn context_single_line_area(area: Rect, checkpoint: bool) -> Rect {
    centered_card(
        area,
        area.width.min(80),
        area.height.min(9 + u16::from(checkpoint)),
    )
}

fn centered_card(area: Rect, width: u16, height: u16) -> Rect {
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

fn choice_content_rows(draft: &ContextEditDraft, width: usize) -> u16 {
    if draft.choice_details {
        return context_choice_detail_lines(draft, width)
            .len()
            .min(u16::MAX as usize) as u16;
    }
    2 + choices(draft).len().clamp(1, 8) as u16
}

pub(super) fn choice_controls(details: bool) -> [&'static str; 2] {
    if details {
        return ["PgUp/Dn read · Enter apply", "Tab list · Esc cancel"];
    }
    [
        "↑↓/PgUp/Dn choose · Enter apply",
        "Tab details · Esc cancel",
    ]
}

fn choices(draft: &ContextEditDraft) -> &[ContextFieldChoice] {
    match &draft.entries[draft.cursor].constraint {
        ContextEditConstraint::Choice(choices) => choices,
        _ => &[],
    }
}

pub(crate) fn context_choice_detail_lines(draft: &ContextEditDraft, width: usize) -> Vec<String> {
    let entry = &draft.entries[draft.cursor];
    let mut text = vec![
        entry.label.clone(),
        "Current value:".into(),
        entry.text().into(),
    ];
    if let Some(choice) = choices(draft).get(draft.choice_cursor) {
        text.extend([
            "Selected choice:".into(),
            choice.label.clone(),
            "Exact value:".into(),
            choice.value.clone(),
        ]);
    } else {
        text.push("No unambiguous component is available. Esc keeps the existing value.".into());
    }
    text.push("Enter applies only this draft field. Review and save are separate.".into());
    if entry
        .pointer
        .as_deref()
        .unwrap_or_default()
        .starts_with("/dfd/flows/")
    {
        text.push("Flow choices use unique component IDs within the edit limits. Ambiguous or unsupported IDs are not offered.".into());
    }
    text.into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect()
}

pub(crate) fn context_choice_lines(
    draft: &ContextEditDraft,
    width: usize,
    height: usize,
) -> Vec<String> {
    if draft.choice_details {
        let lines = context_choice_detail_lines(draft, width);
        let start = draft.scroll.min(lines.len().saturating_sub(height));
        return lines.into_iter().skip(start).take(height).collect();
    }
    choice_list_lines(draft, width, height)
}

fn choice_list_lines(draft: &ContextEditDraft, width: usize, height: usize) -> Vec<String> {
    let entry = &draft.entries[draft.cursor];
    let values = choices(draft);
    let header = height.saturating_sub(1).min(2);
    let mut lines = [
        entry.label.clone(),
        format!("Current: {} · {} choices", entry.text(), values.len()),
    ]
    .into_iter()
    .take(header)
    .map(|line| fit(&line, width))
    .collect::<Vec<_>>();
    if values.is_empty() {
        lines.push(fit("No unambiguous component available", width));
        return lines;
    }
    let count = height.saturating_sub(header);
    let start = draft.choice_cursor.saturating_sub(count.saturating_sub(1));
    lines.extend(
        values
            .iter()
            .enumerate()
            .skip(start)
            .take(count)
            .map(|(index, choice)| {
                let marker = if index == draft.choice_cursor {
                    "▸"
                } else {
                    " "
                };
                fit(
                    &format!("{marker} {} · {}", choice.label, choice.value),
                    width,
                )
            }),
    );
    lines
}
