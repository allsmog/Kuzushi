use super::*;

pub(crate) fn render_threat_patch_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(patch) = app.pending_threat_patch.as_ref() else {
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ THREAT PATCH · goal: {}", patch.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(
            &format!("  summary: {}", patch.summary),
            area.width as usize,
        ),
        theme::primary(),
    ));
    let key_count = match &patch.patch {
        serde_json::Value::Object(map) => map.len(),
        _ => 0,
    };
    lines.push(Line::styled(
        fit(
            &format!("  patch: {key_count} top-level key(s)"),
            area.width as usize,
        ),
        theme::success(),
    ));
    for note in &patch.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    lines.push(Line::styled(
        fit("/threats apply   /threats reject", area.width as usize),
        theme::label(),
    ));
    render_lines(frame, area, lines);
}

pub(crate) fn plan_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(plan) = &app.pending_plan else {
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
