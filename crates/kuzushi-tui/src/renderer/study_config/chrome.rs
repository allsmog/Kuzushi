use super::*;
use crate::ui_view_models::study_config::{
    study_allowance_summary, study_surface_title, study_workload_summary,
};

pub(super) fn render_study_chrome(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    let title = study_surface_title(config);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(format!(" {title} "), theme::heading()))
        .title_bottom(Line::from(format!(" {} ", study_workload_summary(config))).right_aligned());
    frame.render_widget(block, area);
    render_study_target(frame, config, area);
    render_study_allowance(frame, config, area);
}

fn render_study_allowance(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            study_allowance_summary(config, area.width.saturating_sub(4) as usize),
            theme::muted(),
        )),
        Rect::new(area.x + 2, area.y + 2, area.width.saturating_sub(4), 1),
    );
}

pub(in crate::renderer) fn render_study_target(
    frame: &mut Frame<'_>,
    config: &BatchScanConfig,
    area: Rect,
) {
    let target = config
        .target
        .file_name()
        .unwrap_or(config.target.as_os_str())
        .to_string_lossy();
    let target_line = Line::styled(
        fit(
            &format!("Repository: {target}"),
            area.width.saturating_sub(4) as usize,
        ),
        theme::muted(),
    );
    frame.render_widget(
        Paragraph::new(target_line),
        Rect::new(area.x + 2, area.y + 1, area.width.saturating_sub(4), 1),
    );
}
