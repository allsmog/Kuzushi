use super::*;
use ratatui::widgets::{Block, Borders, Clear};

pub(super) fn render_resource_picker(frame: &mut Frame<'_>, app: &ShellApp) {
    let full = frame.area();
    let area = crate::ui_view_models::study_config::study_config_area(full.width, full.height);
    let width = usize::from(area.width.saturating_sub(4));
    let Some(model) = crate::ui_view_models::study_resource_picker::resource_picker_model(
        app,
        width,
        usize::from(area.height),
    ) else {
        return;
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .title(" HISTORICAL USAGE "),
        area,
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
    let body = Rect::new(
        area.x + 2,
        area.y + 3,
        area.width.saturating_sub(4),
        area.height.saturating_sub(6),
    );
    render_picker_body(frame, model, body);
    let controls = Rect::new(body.x, area.bottom().saturating_sub(2), body.width, 1);
    frame.render_widget(
        Paragraph::new("↑↓ Enter · PgUp/Dn · r · Esc back").style(theme::accent()),
        controls,
    );
}

fn render_picker_body(
    frame: &mut Frame<'_>,
    model: crate::ui_view_models::study_resource_picker::ResourcePickerModel,
    body: Rect,
) {
    let list = Rect::new(body.x, body.y, body.width, model.list_rows as u16);
    frame.render_widget(
        Paragraph::new(
            model
                .choices
                .into_iter()
                .map(Line::from)
                .collect::<Vec<_>>(),
        ),
        list,
    );
    let detail = Rect::new(
        body.x,
        body.y + model.list_rows as u16 + 1,
        body.width,
        model.page_rows as u16,
    );
    frame.render_widget(
        Paragraph::new(model.detail.into_iter().map(Line::from).collect::<Vec<_>>()),
        detail,
    );
}
