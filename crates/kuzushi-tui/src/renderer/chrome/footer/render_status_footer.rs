use super::*;
use crate::ui_view_models::status_footer_model;

pub(crate) fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let model = status_footer_model(app);
    let compact = area.width < 80;
    let left = footer_segments(&model.left_segments, &model.compact_left_segments, compact);
    let right = footer_segments(
        &model.right_segments,
        &model.compact_right_segments,
        compact,
    );
    // Prefer the right segment when widths are tight: the top status strip
    // already shows mode + target + ctx, so on narrow terminals truncating
    // the duplicated left side keeps the findings count visible.
    let text = justify_prefer_right(left, right, area.width as usize);
    frame.render_widget(Paragraph::new(Line::styled(text, theme::primary())), area);
}

fn footer_segments(wide: &[String], compact: &[String], use_compact: bool) -> String {
    join_segments(if use_compact { compact } else { wide })
}
