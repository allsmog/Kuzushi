use super::*;

pub(super) fn render_regeneration_guidance(
    frame: &mut Frame<'_>,
    generation: &crate::app::StudyContextGeneration,
    area: Rect,
) {
    let Some(editor) = generation.guidance_editor.as_ref() else {
        frame.render_widget(
            Paragraph::new(crate::ui_view_models::context_generation::GUIDANCE_EDITOR_UNAVAILABLE)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(guidance_title(generation)),
                ),
            area,
        );
        return;
    };
    render_guidance_editor(frame, generation, editor, area);
}

fn render_guidance_editor(
    frame: &mut Frame<'_>,
    generation: &crate::app::StudyContextGeneration,
    editor: &crate::app::FieldEditor,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(guidance_title(generation));
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let body = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(3),
        ..inner
    };
    render_guidance_notice(frame, generation, Rect { height: 1, ..inner });
    let lines = crate::renderer::shared::field_editor_lines(
        editor,
        body.width as usize,
        body.height as usize,
    );
    frame.render_widget(Paragraph::new(lines), body);
    render_guidance_controls(
        frame,
        Rect {
            y: inner.bottom().saturating_sub(2),
            height: 2,
            ..inner
        },
        generation.editor_limit(),
    );
}

fn render_guidance_notice(
    frame: &mut Frame<'_>,
    generation: &crate::app::StudyContextGeneration,
    area: Rect,
) {
    let notice = generation
        .guidance_notice
        .as_deref()
        .unwrap_or("Guidance only · no model request");
    frame.render_widget(
        Paragraph::new(fit(notice, area.width as usize)).style(theme::muted()),
        area,
    );
}

fn guidance_title(generation: &crate::app::StudyContextGeneration) -> &'static str {
    if generation.is_workflow_proposal() {
        return " PLANNING GOAL ";
    }
    if generation.is_question() {
        " QUESTION "
    } else if generation.is_lesson() {
        " LESSON GUIDANCE "
    } else {
        " REGENERATION GUIDANCE "
    }
}

fn render_guidance_controls(frame: &mut Frame<'_>, area: Rect, limit: usize) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("Enter newline · Ctrl+S use text"),
            Line::from(format!("Esc back · draft kept · max {limit} B")),
        ]),
        area,
    );
}

pub(super) fn render_regeneration_controls(frame: &mut Frame<'_>, area: Rect, has_result: bool) {
    let action = if has_result {
        "Enter inspect · n new · Esc back"
    } else {
        "Enter next · n new · Esc back"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("t calls · r review · M model", theme::accent()),
            Line::styled("G guide · Tab options · PgUp/Dn", theme::accent()),
            Line::styled(action, theme::accent()),
        ]),
        area,
    );
}

pub(super) fn render_diagnostic_controls(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("d / Esc back · PgUp/Dn read", theme::accent()),
            Line::styled("Unaccepted · source text", theme::muted()),
        ]),
        area,
    );
}

pub(super) fn render_generation_document(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    body: Rect,
    scroll: usize,
) -> (usize, usize) {
    let lines = generation_lines(app, body.width as usize);
    let max = lines.len().saturating_sub(body.height as usize);
    let offset = scroll.min(max);
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(body.height as usize)
        .enumerate()
        .map(|(index, line)| {
            Line::styled(
                line,
                if offset + index == 0 {
                    theme::heading()
                } else {
                    theme::primary()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), body);
    (offset, max)
}

pub(super) fn render_generation_border(
    frame: &mut Frame<'_>,
    area: Rect,
    has_result: bool,
    scopes: bool,
    position: (usize, usize),
    diagnostic: bool,
    title_override: Option<&'static str>,
) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(
            title_override.unwrap_or_else(|| generation_title(has_result, scopes, diagnostic)),
            theme::heading(),
        ));
    if scopes || diagnostic || title_override.is_some() {
        block = block.title_bottom(Span::styled(
            format!(" PgUp/Dn {}/{} ", position.0 + 1, position.1 + 1),
            theme::muted(),
        ));
    }
    frame.render_widget(block, area);
}

pub(super) fn regeneration_title(has_result: bool) -> &'static str {
    if has_result {
        " REGENERATION RESULT "
    } else {
        " REGENERATE CONTEXT TEXT "
    }
}

fn generation_title(has_result: bool, scopes: bool, diagnostic: bool) -> &'static str {
    if diagnostic {
        return " REJECTED CONTEXT OUTPUT ";
    }
    if scopes {
        return " SUGGEST SCAN SCOPES ";
    }
    if has_result {
        " CONTEXT JOB RESULT "
    } else {
        " GENERATE STUDY CONTEXT "
    }
}

pub(super) fn render_generation_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    offset: usize,
    max: usize,
    has_context: bool,
    scopes: bool,
    rejected_available: bool,
    editable: bool,
) {
    let nav = generation_controls_navigation(
        area.width,
        has_context,
        (offset, max),
        scopes,
        rejected_available,
        editable,
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(nav, theme::muted()),
            Line::styled(
                if has_context {
                    "Enter inspect · n new · Esc back"
                } else {
                    "Enter next · n new draft · Esc back"
                },
                theme::accent(),
            ),
        ]),
        area,
    );
}

fn generation_controls_navigation(
    width: u16,
    has_context: bool,
    position: (usize, usize),
    scopes: bool,
    rejected_available: bool,
    editable: bool,
) -> String {
    if scopes {
        return "t calls · r review · M model · Tab".into();
    }
    if rejected_available {
        return "d output · Tab options · PgUp/Dn".into();
    }
    if editable {
        return "t calls · r review · s save · Tab".into();
    }
    generation_navigation(width, has_context, position.0, position.1)
}

fn generation_navigation(width: u16, has_context: bool, offset: usize, max: usize) -> String {
    match (has_context, width < 50) {
        (true, true) => "m Map · Tab · PgUp/Dn".into(),
        (true, false) => "m Review Map · Tab options · PgUp/Dn".into(),
        (false, true) => "t calls · r review · Tab · PgUp/Dn".into(),
        (false, false) => format!(
            "t calls · r review · Tab options · PgUp/Dn {}/{}",
            offset + 1,
            max + 1
        ),
    }
}
