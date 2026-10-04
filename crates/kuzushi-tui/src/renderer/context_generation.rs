use super::*;
use crate::ui_view_models::context_generation::{generation_body, generation_lines};
use ratatui::widgets::{Block, Borders};

pub(super) fn render_context_generation(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(generation) = app.context_generation() else {
        return;
    };
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(Span::styled(" GENERATE STUDY CONTEXT ", theme::heading())),
        area,
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
    let viewport = frame.area();
    let body = generation_body(viewport.width, viewport.height);
    let lines = generation_lines(app, body.width as usize);
    let max = lines.len().saturating_sub(body.height as usize);
    let offset = generation.scroll.min(max);
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
    let controls = Rect::new(body.x, area.bottom().saturating_sub(3), body.width, 2);
    render_generation_controls(frame, controls, offset, max);
}

fn render_generation_controls(frame: &mut Frame<'_>, area: Rect, offset: usize, max: usize) {
    let nav = if area.width < 50 {
        "t calls · r review · Tab · PgUp/Dn".into()
    } else {
        format!(
            "t calls · r review · Tab options · PgUp/Dn {}/{}",
            offset + 1,
            max + 1
        )
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(nav, theme::muted()),
            Line::styled("Enter next · n new draft · Esc back", theme::accent()),
        ]),
        area,
    );
}
