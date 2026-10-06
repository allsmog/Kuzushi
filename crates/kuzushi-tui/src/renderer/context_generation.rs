use super::*;
use crate::ui_view_models::context_generation::{generation_body, generation_lines};
use ratatui::widgets::{Block, Borders};

pub(super) fn render_context_generation(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(generation) = app.context_generation() else {
        return;
    };
    let viewport = frame.area();
    let body = generation_body(viewport.width, viewport.height);
    let (offset, max) = render_generation_document(frame, app, body, generation.scroll);
    render_generation_border(
        frame,
        area,
        generation.has_result() || generation.result_error.is_some(),
        generation.is_scope_proposal(),
        (offset, max),
        generation.show_rejected,
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
    let controls = Rect::new(body.x, area.bottom().saturating_sub(3), body.width, 2);
    if generation.show_rejected {
        render_diagnostic_controls(frame, controls);
        return;
    }
    render_generation_controls(
        frame,
        controls,
        offset,
        max,
        generation.has_result(),
        generation.is_scope_proposal(),
        generation.rejected_available,
        generation.receipt.is_none(),
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
) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(
            generation_title(has_result, scopes, diagnostic),
            theme::heading(),
        ));
    if scopes || diagnostic {
        block = block.title_bottom(Span::styled(
            format!(" PgUp/Dn {}/{} ", position.0 + 1, position.1 + 1),
            theme::muted(),
        ));
    }
    frame.render_widget(block, area);
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
