use super::*;
use crate::ui_view_models::{
    review_study::{review_controls, review_study_lines},
    study_config::study_projection,
};
use ratatui::widgets::{Block, Borders};

pub(super) fn render_review_study(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(config) = study_projection(app) else {
        return;
    };
    let Some(review) = config.review_plan.as_ref() else {
        return;
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" PLAN FINDING REVIEW ");
    frame.render_widget(block, area);
    let body = Rect::new(
        area.x + 2,
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(7),
    );
    let lines = review_study_lines(
        &config,
        app.config().model.as_deref(),
        usize::from(body.width),
    );
    let max = lines.len().saturating_sub(usize::from(body.height));
    let offset = review.scroll.min(max);
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(offset)
                .take(usize::from(body.height))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        body,
    );
    frame.render_widget(
        Paragraph::new(review_controls()),
        Rect::new(body.x, area.bottom().saturating_sub(5), body.width, 4),
    );
}
