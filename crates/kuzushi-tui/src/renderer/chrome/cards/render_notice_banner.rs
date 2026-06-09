use super::*;
use crate::ui_view_models::notice_banner_model;
use crate::NoticeSeverity;

pub(crate) fn render_notice_banner(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(notice) = notice_banner_model(app) else {
        return;
    };
    // Chip-style banner mirroring the rate-limit banner: a coloured chip pops
    // first, then source + message. Error is red, Warn is amber.
    let (chip, chip_style) = match notice.severity {
        NoticeSeverity::Error => (" ERROR ", theme::danger()),
        NoticeSeverity::Warn => (" NOTICE ", theme::warn()),
    };
    let used = chip.len() + notice.source.chars().count() + 8;
    let message = fit(
        &notice.message,
        (area.width as usize).saturating_sub(used).max(8),
    );
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(chip, chip_style),
        Span::raw("  "),
        Span::styled(notice.source.clone(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled(message, theme::muted()),
        Span::styled("  Esc dismiss", theme::subtle()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}
