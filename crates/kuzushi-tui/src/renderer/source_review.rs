use super::*;
use crate::app::source_review::SourceReviewMode;
use crate::ui_view_models::source_review::{
    source_review_controls, source_review_header_lines, source_review_title,
};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    let Some(form) = app.source_review_form() else {
        return false;
    };
    let area = frame.area();
    let block = ratatui::widgets::Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .title(source_review_title(form))
        .border_style(theme::subtle());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(
            source_review_header_lines(form, chunks[0].width as usize)
                .into_iter()
                .map(Line::raw)
                .collect::<Vec<_>>(),
        )
        .style(theme::heading()),
        chunks[0],
    );
    render_body(frame, form, chunks[1]);
    frame.render_widget(
        Paragraph::new(source_review_controls(form.mode))
            .wrap(ratatui::widgets::Wrap { trim: false })
            .style(theme::accent()),
        chunks[2],
    );
    true
}

fn render_body(
    frame: &mut Frame<'_>,
    form: &crate::app::source_review::SourceReviewForm,
    area: Rect,
) {
    if form.mode == SourceReviewMode::Reason {
        render_reason(frame, form, area);
        return;
    }
    let wrapped = crate::ui_view_models::source_review::source_review_wrapped_lines(
        form,
        area.width as usize,
    );
    let max = wrapped.len().saturating_sub(area.height as usize);
    let scroll = if form.mode == SourceReviewMode::Verdict {
        form.verdict
            .saturating_sub(area.height.saturating_sub(1) as usize)
    } else {
        form.scroll
    };
    frame.render_widget(
        Paragraph::new(
            wrapped
                .into_iter()
                .skip(scroll.min(max))
                .take(area.height as usize)
                .map(Line::raw)
                .collect::<Vec<_>>(),
        ),
        area,
    );
}

fn render_reason(
    frame: &mut Frame<'_>,
    form: &crate::app::source_review::SourceReviewForm,
    area: Rect,
) {
    let heading = form.notice.clone().unwrap_or_else(|| {
        format!(
            "Verdict: {}",
            crate::app::source_review::SOURCE_VERDICTS
                .get(form.verdict)
                .map_or("not selected", |(_, label)| *label)
        )
    });
    frame.render_widget(
        Paragraph::new(fit(&heading, area.width as usize)).style(theme::accent()),
        Rect::new(area.x, area.y, area.width, area.height.min(1)),
    );
    let area = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(1),
    );
    frame.render_widget(
        Paragraph::new(crate::renderer::shared::field_editor_lines(
            &form.reason,
            area.width as usize,
            area.height as usize,
        )),
        area,
    );
}
