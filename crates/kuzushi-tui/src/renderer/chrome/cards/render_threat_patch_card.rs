use super::*;
use crate::ui_view_models::{plan_card_model, threat_patch_card_model};

pub(crate) fn render_threat_patch_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(patch) = threat_patch_card_model(app) else {
        return;
    };
    let width = area.width as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(threat_patch_line(
        format!("◆ THREAT PATCH · goal: {}", patch.goal),
        width,
        theme::accent(),
    ));
    lines.push(threat_patch_line(
        format!("  summary: {}", patch.summary),
        width,
        theme::primary(),
    ));
    lines.push(threat_patch_line(
        format!("  patch: {} top-level key(s)", patch.top_level_keys),
        width,
        theme::success(),
    ));
    for note in &patch.unsupported {
        lines.push(threat_patch_line(
            format!("  ! unsupported: {note}"),
            width,
            theme::warn(),
        ));
    }
    lines.push(threat_patch_line(
        "/threats apply   /threats reject".to_string(),
        width,
        theme::label(),
    ));
    render_lines(frame, area, lines);
}

fn threat_patch_line(text: String, width: usize, style: Style) -> Line<'static> {
    Line::styled(fit(&text, width), style)
}

pub(crate) fn plan_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(plan) = plan_card_model(app) else {
        return 0;
    };
    let body = (plan.changes.len() + plan.unsupported.len()) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}

pub(crate) fn render_throttle_banner(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(throttle) = &app.advisory.throttle else {
        return;
    };
    // Chip-style banner per `design/mockups/rate-limited.jsx`:
    //   ` RATE LIMIT  <source> · <message>`
    // The chip itself stays warn-tinted so it pops; the source label is
    // primary and the message muted so the eye lands on the chip first.
    let source_budget = (area.width as usize).saturating_sub(15 + throttle.source.chars().count());
    let message = fit(&throttle.message, source_budget.max(8));
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(" RATE LIMIT ", theme::warn()),
        Span::raw("  "),
        Span::styled(throttle.source.clone(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled(message, theme::muted()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}
