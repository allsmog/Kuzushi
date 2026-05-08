use super::*;

pub(crate) fn confirm_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    if app.advisory.pending_confirm.is_none() {
        return 0;
    }
    // Header + 3 detail rows (tool, target, rationale/allowlist) + key
    // row.  Up to 6 rows; clamp so very narrow viewports still get a
    // 3-row minimum.
    6.min(area.height.saturating_sub(8) as u16).max(3)
}

pub(crate) fn render_confirm_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(confirm) = app.advisory.pending_confirm.as_ref() else {
        return;
    };
    let (header_glyph, header_style) = match confirm.kind {
        crate::app::ConfirmKind::DestructiveVerb => ("✗", theme::danger()),
        _ => ("⚠", theme::warn()),
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{header_glyph} "), header_style),
        Span::styled(confirm.kind.label().to_string(), header_style),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("tool      ", theme::muted()),
        Span::styled(confirm.tool.clone(), theme::primary()),
        Span::raw("   "),
        Span::styled("target ", theme::muted()),
        Span::styled(
            fit(&confirm.target, (area.width as usize).saturating_sub(40)),
            theme::primary(),
        ),
    ]));
    if let Some(actor) = &confirm.actor {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("actor     ", theme::muted()),
            Span::styled(actor.clone(), theme::primary()),
        ]));
    }
    if let Some(rationale) = &confirm.rationale {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("rationale ", theme::muted()),
            Span::styled(
                fit(rationale, (area.width as usize).saturating_sub(14)),
                theme::primary(),
            ),
        ]));
    }
    if let Some(allowlist) = &confirm.allowlist {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("allowlist ", theme::muted()),
            Span::styled(
                fit(allowlist, (area.width as usize).saturating_sub(14)),
                theme::muted(),
            ),
        ]));
    }
    if confirm.kind.allows_yes() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("y", theme::success()),
            Span::raw(" "),
            Span::styled("allow once", theme::muted()),
            Span::raw("   "),
            Span::styled("Y", theme::success()),
            Span::raw(" "),
            Span::styled("allow + remember", theme::muted()),
            Span::raw("   "),
            Span::styled("n", theme::danger()),
            Span::raw(" "),
            Span::styled("deny once", theme::muted()),
            Span::raw("   "),
            Span::styled("N", theme::danger()),
            Span::raw(" "),
            Span::styled("deny + add to denylist", theme::muted()),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("rule      ", theme::muted()),
            Span::styled(
                "destructive verb · always refused (no override)".to_string(),
                theme::danger(),
            ),
        ]));
    }
    render_lines(frame, area, lines);
}

pub(crate) fn threat_patch_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(patch) = &app.pending_threat_patch else {
        return 0;
    };
    let body = (patch.unsupported.len() + 1) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}
