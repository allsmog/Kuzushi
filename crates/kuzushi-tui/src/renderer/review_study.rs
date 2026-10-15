use super::*;
use crate::ui_view_models::{
    review_study::{review_body_height, review_controls, review_study_lines},
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
        review_body_height(&config, area.height),
    );
    let lines = review_study_lines(
        &config,
        app.config().model.as_deref(),
        usize::from(body.width),
    );
    let max = lines.len().saturating_sub(usize::from(body.height));
    let offset = review.scroll.min(max);
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(usize::from(body.height))
        .collect::<Vec<_>>()
        .join("\n");
    frame.render_widget(Paragraph::new(visible), body);
    render_controls(frame, area, body, &config);
}

fn render_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    body: Rect,
    config: &crate::app::BatchScanConfig,
) {
    let controls = review_controls(&config);
    let rows = controls.lines().count() as u16;
    frame.render_widget(
        Paragraph::new(controls),
        Rect::new(
            body.x,
            area.bottom().saturating_sub(rows + 1),
            body.width,
            rows,
        ),
    );
}
