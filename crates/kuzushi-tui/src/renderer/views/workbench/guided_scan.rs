use crate::app::{GuidedScanQuestionModel, WorkbenchPage};
use crate::renderer::shared::prompt_segments;
use crate::renderer::shared::text::{fit, pad};
use crate::renderer::theme;
use ratatui::layout::Rect;
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::Modifier;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

pub(in crate::renderer) fn guided_question_height(
    area: Rect,
    model: &GuidedScanQuestionModel,
) -> u16 {
    let desired = model.options.len() as u16
        + 4
        + model.detail_lines.len() as u16
        + u16::from(model.other_open)
        + u16::from(model.acknowledgement.is_some())
        + u16::from(model.error.is_some());
    let available = area.height.saturating_sub(cockpit_reserve(area.height));
    let maximum = area.height.saturating_mul(45).div_ceil(100).max(5);
    desired.min(maximum).min(available).max(available.min(3))
}

fn cockpit_reserve(height: u16) -> u16 {
    2 + u16::from(height > 6)
}

pub(in crate::renderer) fn render_guided_question(
    frame: &mut Frame<'_>,
    area: Rect,
    page: WorkbenchPage,
    model: &GuidedScanQuestionModel,
) {
    if area.width < 4 || area.height < 3 {
        return;
    }
    let accent = phase_style(page);
    let title = question_title(model);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(accent)
        .title(Span::styled(title, accent));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = guided_question_lines_for_height(
        model,
        inner.width as usize,
        inner.height as usize,
        accent,
    );
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

pub(super) fn guided_question_lines(
    model: &GuidedScanQuestionModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = question_intro_lines(model, width, true, model.detail_lines.len());
    append_option_window(
        &mut lines,
        model,
        width,
        model.options.len(),
        theme::accent(),
    );
    append_other_editor(&mut lines, model, width);
    append_question_acknowledgement(&mut lines, model, width);
    append_question_error(&mut lines, model, width);
    lines.push(question_footer_line(model, width));
    lines
}

fn guided_question_lines_for_height(
    model: &GuidedScanQuestionModel,
    width: usize,
    height: usize,
    accent: ratatui::style::Style,
) -> Vec<Line<'static>> {
    let tail_rows = 1
        + usize::from(model.other_open)
        + usize::from(model.acknowledgement.is_some())
        + usize::from(model.error.is_some());
    let minimum_option_rows = usize::from(!model.options.is_empty());
    let detail_budget = height
        .saturating_sub(1 + tail_rows + minimum_option_rows)
        .min(model.detail_lines.len());
    let mut lines = question_intro_lines(model, width, false, detail_budget);
    let option_rows = height.saturating_sub(lines.len() + tail_rows);
    append_option_window(&mut lines, model, width, option_rows, accent);
    append_other_editor(&mut lines, model, width);
    append_question_acknowledgement(&mut lines, model, width);
    append_question_error(&mut lines, model, width);
    if lines.len() < height {
        lines.push(question_footer_line(model, width));
    }
    lines.truncate(height);
    lines
}

fn append_question_acknowledgement(
    lines: &mut Vec<Line<'static>>,
    model: &GuidedScanQuestionModel,
    width: usize,
) {
    if let Some(message) = model.acknowledgement.as_deref() {
        lines.push(Line::from(Span::styled(
            fit(&format!(" ✓ {message}"), width),
            theme::success(),
        )));
    }
}

fn question_intro_lines(
    model: &GuidedScanQuestionModel,
    width: usize,
    include_progress: bool,
    detail_budget: usize,
) -> Vec<Line<'static>> {
    // Semantic source keys intentionally terminate at this styling boundary.
    let _semantic_source_keys = &model.semantic_keys;
    let mut lines = vec![Line::from(Span::styled(
        fit(&model.prompt, width),
        theme::primary().add_modifier(Modifier::BOLD),
    ))];
    if width >= 54 {
        lines.extend(
            model
                .detail_lines
                .iter()
                .take(detail_budget)
                .map(|detail| Line::from(Span::styled(fit(detail, width), theme::muted()))),
        );
    }
    if include_progress {
        if let Some(progress) = model.progress.as_deref() {
            lines.push(Line::from(Span::styled(
                progress.to_string(),
                theme::label(),
            )));
        }
    }
    lines
}

fn append_option_window(
    lines: &mut Vec<Line<'static>>,
    model: &GuidedScanQuestionModel,
    width: usize,
    budget: usize,
    accent: ratatui::style::Style,
) {
    let (start, end) = visible_option_range(model, budget);
    lines.extend((start..end).map(|index| {
        option_line(
            index,
            &model.options[index],
            index == model.cursor,
            model.multi_select,
            width,
            accent,
        )
    }));
}

fn append_other_editor(
    lines: &mut Vec<Line<'static>>,
    model: &GuidedScanQuestionModel,
    width: usize,
) {
    if model.other_open {
        let editor = prompt_segments(
            " Other › ",
            &model.other_draft,
            model.other_cursor,
            width,
            "▏",
        );
        lines.push(Line::from(vec![
            Span::styled(editor.prompt, theme::warn()),
            Span::styled(editor.before_cursor, theme::primary()),
            Span::styled(editor.cursor_text, theme::cursor_block()),
            Span::styled(editor.after_cursor, theme::primary()),
        ]));
    }
}

fn append_question_error(
    lines: &mut Vec<Line<'static>>,
    model: &GuidedScanQuestionModel,
    width: usize,
) {
    if let Some(error) = model.error.as_deref() {
        lines.push(Line::from(Span::styled(
            fit(&format!(" ! {error}"), width),
            theme::danger(),
        )));
    }
}

fn question_footer_line(model: &GuidedScanQuestionModel, width: usize) -> Line<'static> {
    let text = if model.other_open {
        "Enter submit · Esc return".to_string()
    } else if model.multi_select {
        "↑/↓ move · Space toggle · c continue · Enter choose · Tab Other · Esc dismiss".to_string()
    } else if model.options.iter().any(|option| option.other) {
        "↑/↓ move · Enter choose · Tab Other · Esc dismiss".to_string()
    } else {
        "↑/↓ move · Enter choose · Esc dismiss".to_string()
    };
    let defaults = if model.accept_remaining_defaults && !model.other_open {
        " · a accept defaults"
    } else {
        ""
    };
    let position = if model.options.is_empty() {
        String::new()
    } else {
        format!("{}/{} · ", model.cursor + 1, model.options.len())
    };
    Line::from(Span::styled(
        fit(&format!(" {position}{text}{defaults}"), width),
        theme::subtle(),
    ))
}

fn option_line(
    index: usize,
    option: &crate::app::GuidedQuestionOption,
    focused: bool,
    multi_select: bool,
    width: usize,
    accent: ratatui::style::Style,
) -> Line<'static> {
    let cursor = if focused { "›" } else { " " };
    let mark = option_mark(option.selected, focused, multi_select);
    let recommendation = if option.recommended {
        "  RECOMMENDED"
    } else {
        ""
    };
    let label = format!(
        " {cursor} {:>2} {mark} {}{recommendation}",
        index + 1,
        option.label
    );
    let text = option_row_text(&label, option, focused, width);
    let style = if focused {
        accent
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::REVERSED)
    } else if option.recommended {
        theme::primary()
    } else {
        theme::muted()
    };
    let text = if focused { pad(&text, width) } else { text };
    Line::from(Span::styled(text, style))
}

fn option_mark(selected: bool, focused: bool, multi_select: bool) -> &'static str {
    if multi_select {
        if selected {
            "[x]"
        } else {
            "[ ]"
        }
    } else if focused {
        "●"
    } else {
        "○"
    }
}

fn option_row_text(
    label: &str,
    option: &crate::app::GuidedQuestionOption,
    focused: bool,
    width: usize,
) -> String {
    if !focused || width < 86 {
        return fit(label, width);
    }
    fit(&format!("{label} · {}", option.description), width)
}

fn visible_option_range(model: &GuidedScanQuestionModel, budget: usize) -> (usize, usize) {
    let count = model.options.len();
    let visible = budget.min(count);
    if visible == 0 {
        return (0, 0);
    }
    let start = model
        .cursor
        .saturating_sub(visible / 2)
        .min(count.saturating_sub(visible));
    (start, start + visible)
}

fn question_title(model: &GuidedScanQuestionModel) -> String {
    let progress = model.progress.as_deref().map_or_else(String::new, |value| {
        format!(" · {}", value.to_ascii_uppercase())
    });
    format!(" {}{progress} ", model.header)
}

fn phase_style(page: WorkbenchPage) -> ratatui::style::Style {
    match page {
        WorkbenchPage::Map => theme::mode_map(),
        WorkbenchPage::Scan => theme::mode_scan(),
        WorkbenchPage::Review => theme::mode_review(),
        WorkbenchPage::Prove => theme::mode_prove(),
        WorkbenchPage::Fix => theme::mode_fix(),
    }
}

#[cfg(test)]
mod tests;
