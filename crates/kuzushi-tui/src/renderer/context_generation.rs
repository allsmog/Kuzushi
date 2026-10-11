use super::*;
use crate::ui_view_models::context_generation::{generation_body, generation_lines};
use ratatui::widgets::{Block, Borders};

pub(super) fn render_context_generation(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(generation) = app.context_generation() else {
        return;
    };
    if generation.guidance_editing {
        render_regeneration_guidance(frame, generation, area);
        return;
    }
    let viewport = frame.area();
    let body = generation_body(
        viewport.width,
        viewport.height,
        generation.is_regeneration()
            || generation.is_lesson()
            || generation.supports_brief_guidance(),
    );
    let (offset, max) = render_generation_document(frame, app, body, generation.scroll);
    render_generation_border(
        frame,
        area,
        generation.has_result() || generation.result_error.is_some(),
        generation.is_scope_proposal(),
        (offset, max),
        generation.show_rejected,
        generation_title_override(generation),
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
    let controls = generation_controls_area(area, body, generation);
    render_generation_state_controls(frame, controls, generation, (offset, max));
}

fn generation_controls_area(
    area: Rect,
    body: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> Rect {
    let height = if generation.is_regeneration()
        || generation.is_lesson()
        || generation.supports_brief_guidance()
    {
        3
    } else {
        2
    };
    Rect::new(
        body.x,
        area.bottom().saturating_sub(height + 1),
        body.width,
        height,
    )
}

fn render_generation_state_controls(
    frame: &mut Frame<'_>,
    controls: Rect,
    generation: &crate::app::StudyContextGeneration,
    position: (usize, usize),
) {
    if render_generation_reader_controls(frame, controls, generation)
        || render_generation_editor_controls(frame, controls, generation)
    {
        return;
    }
    render_generation_controls(
        frame,
        controls,
        position.0,
        position.1,
        generation.has_result(),
        generation.is_scope_proposal(),
        generation.rejected_available,
        generation.receipt.is_none(),
    );
}

fn render_generation_reader_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> bool {
    if generation.show_brief_guidance {
        frame.render_widget(Paragraph::new("PgUp/Dn read\nEsc back · frozen goal"), area);
        return true;
    }
    if generation.show_rejected {
        render_diagnostic_controls(frame, area);
        return true;
    }
    false
}

fn render_generation_editor_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> bool {
    if generation.supports_brief_guidance() {
        render_goal_generation_controls(frame, area, generation);
        return true;
    }
    if generation.is_regeneration() {
        render_regeneration_controls(frame, area, generation.has_result());
        return true;
    }
    if generation.is_lesson() {
        render_lesson_controls(frame, area, generation.has_result());
        return true;
    }
    false
}

fn render_goal_generation_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) {
    let navigation = if generation.receipt.is_none() {
        "g guide · b goal · Tab · PgUp/Dn"
    } else {
        "b goal · Tab options · PgUp/Dn"
    };
    let primary = if generation.has_result() && !generation.is_scope_context() {
        "m Map · b goal · Tab · PgUp/Dn"
    } else {
        "t calls · r review · s retention"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(primary, theme::muted()),
            Line::styled(navigation, theme::muted()),
            Line::styled(
                if generation.has_result() {
                    "Enter inspect · n new · Esc back"
                } else {
                    "Enter next · n new · Esc back"
                },
                theme::accent(),
            ),
        ]),
        area,
    );
}

fn generation_title_override(
    generation: &crate::app::StudyContextGeneration,
) -> Option<&'static str> {
    if generation.is_scope_context() {
        return Some(if generation.has_result() {
            " FILE-GROUP CONTEXT DRAFT "
        } else {
            " GENERATE FILE-GROUP CONTEXT "
        });
    }
    if generation.is_lesson() {
        return Some(if generation.has_result() {
            " GENERATED LESSON DRAFT "
        } else {
            " GENERATE LESSON DRAFT "
        });
    }
    generation
        .is_regeneration()
        .then(|| regeneration_title(generation.has_result()))
}

fn render_lesson_controls(frame: &mut Frame<'_>, area: Rect, has_result: bool) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("t calls · r review · M model", theme::muted()),
            Line::styled("G guidance · Tab options · PgUp/Dn", theme::muted()),
            Line::styled(
                if has_result {
                    "Enter inspect lesson · n new · Esc back"
                } else {
                    "Enter next · n new · Esc back"
                },
                theme::accent(),
            ),
        ]),
        area,
    );
}

fn render_regeneration_guidance(
    frame: &mut Frame<'_>,
    generation: &crate::app::StudyContextGeneration,
    area: Rect,
) {
    let editor = generation.guidance_editor.as_ref().unwrap();
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
    let notice = generation
        .guidance_notice
        .as_deref()
        .unwrap_or("Guidance only · no model request");
    frame.render_widget(
        Paragraph::new(fit(notice, inner.width as usize)).style(theme::muted()),
        Rect { height: 1, ..inner },
    );
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
    );
}

fn guidance_title(generation: &crate::app::StudyContextGeneration) -> &'static str {
    if generation.is_lesson() {
        " LESSON GUIDANCE "
    } else {
        " REGENERATION GUIDANCE "
    }
}

fn render_guidance_controls(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("Enter newline · Ctrl+S use guidance"),
            Line::from("Esc back · draft kept · max 2048 B"),
        ]),
        area,
    );
}

fn render_regeneration_controls(frame: &mut Frame<'_>, area: Rect, has_result: bool) {
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

fn render_diagnostic_controls(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("d / Esc back · PgUp/Dn read", theme::accent()),
            Line::styled("Unaccepted · source text", theme::muted()),
        ]),
        area,
    );
}

fn render_generation_document(
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

fn render_generation_border(
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

fn regeneration_title(has_result: bool) -> &'static str {
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

fn render_generation_controls(
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
