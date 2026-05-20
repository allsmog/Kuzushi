//! M3 §3.3 — completion popup rendered just above the prompt when an
//! interactive completion cycle is active. The popup is purely
//! informational: Tab continues to cycle the candidates inline, the
//! popup just makes the list discoverable. Esc closes the popup and
//! restores the operator's original prefix.

pub(in crate::renderer) use super::*;

/// Maximum number of candidate rows shown in the popup. The title row is
/// rendered above this in addition to the candidate rows.
const MAX_POPUP_ROWS: usize = 6;

pub(crate) fn render_completion_popup(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(cycle) = app.completion_cycle.as_ref() else {
        return;
    };
    if cycle.candidates.is_empty() {
        return;
    }
    let visible = MAX_POPUP_ROWS.min(cycle.candidates.len());
    let title = popup_title_line(cycle.candidates.len(), &cycle.prefix, area.width as usize);
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(visible + 1);
    lines.push(title);
    for (offset, candidate) in popup_rows(cycle).take(visible).enumerate() {
        lines.push(popup_row_line(candidate, offset, cycle, area.width as usize));
    }
    render_lines(frame, area, lines);
}

pub(crate) fn completion_popup_height(app: &ShellApp, area: Rect) -> u16 {
    let Some(cycle) = app.completion_cycle.as_ref() else {
        return 0;
    };
    if cycle.candidates.is_empty() || area.height < 6 {
        return 0;
    }
    let visible = MAX_POPUP_ROWS.min(cycle.candidates.len());
    (visible as u16) + 1
}

struct PopupRow<'a> {
    text: &'a str,
    index: usize,
}

fn popup_rows(cycle: &CompletionCycle) -> impl Iterator<Item = PopupRow<'_>> {
    let start = if cycle.index == usize::MAX {
        0
    } else {
        cycle
            .index
            .saturating_sub(MAX_POPUP_ROWS - 1)
            .min(cycle.candidates.len().saturating_sub(MAX_POPUP_ROWS))
    };
    cycle
        .candidates
        .iter()
        .enumerate()
        .skip(start)
        .map(|(index, text)| PopupRow { text, index })
}

fn popup_title_line(total: usize, prefix: &str, width: usize) -> Line<'static> {
    let label = format!(
        " {total} options matching `{prefix}` — Tab cycles · Enter selects · Esc restores"
    );
    Line::styled(fit(&label, width), theme::muted())
}

fn popup_row_line(
    candidate: PopupRow<'_>,
    _offset: usize,
    cycle: &CompletionCycle,
    width: usize,
) -> Line<'static> {
    let is_selected = cycle.index != usize::MAX && cycle.index == candidate.index;
    let marker = if is_selected { "▶ " } else { "  " };
    let row_text = fit(&format!("{marker}{}", candidate.text), width);
    let style = if is_selected {
        theme::accent()
    } else {
        theme::primary()
    };
    Line::styled(row_text, style)
}
