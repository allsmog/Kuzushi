use super::*;

pub(in crate::renderer) fn confirm_card_height(app: &ShellApp, area: Rect) -> u16 {
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

pub(in crate::renderer) fn prereq_prompt_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    if app.pending_prereq_prompt.is_none() {
        return 0;
    }
    // Header + tool/artifact + final tool + key row = 4 rows.
    4.min(area.height.saturating_sub(8) as u16).max(3)
}

pub(in crate::renderer) fn render_prereq_prompt_card(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
) {
    if area.height == 0 {
        return;
    }
    let Some(prompt) = app.pending_prereq_prompt.as_ref() else {
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("◆ ", theme::accent()),
        Span::styled("PREREQUISITE EXISTS", theme::accent()),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("artifact ", theme::muted()),
        Span::styled(
            fit(
                &prompt.current_artifact_label,
                (area.width as usize).saturating_sub(14),
            ),
            theme::primary(),
        ),
        Span::raw("   "),
        Span::styled("path ", theme::muted()),
        Span::styled(
            fit(
                &prompt.current_artifact_path.display().to_string(),
                (area.width as usize).saturating_sub(40),
            ),
            theme::muted(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("for      ", theme::muted()),
        Span::styled(prompt.final_tool.clone(), theme::primary()),
        Span::raw("   "),
        Span::styled("regen via ", theme::muted()),
        Span::styled(prompt.current_tool.clone(), theme::primary()),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("r", theme::success()),
        Span::raw(" "),
        Span::styled("reuse existing", theme::muted()),
        Span::raw("   "),
        Span::styled("g", theme::warn()),
        Span::raw(" "),
        Span::styled("regenerate", theme::muted()),
        Span::raw("   "),
        Span::styled("(y/n also accepted)", theme::muted()),
    ]));
    render_lines(frame, area, lines);
}

pub(in crate::renderer) fn render_confirm_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
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

pub(in crate::renderer) fn threat_patch_card_height(app: &ShellApp, area: Rect) -> u16 {
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

pub(in crate::renderer) fn render_threat_patch_card(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
) {
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

pub(in crate::renderer) fn plan_card_height(app: &ShellApp, area: Rect) -> u16 {
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

pub(in crate::renderer) fn render_throttle_banner(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
) {
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

pub(in crate::renderer) fn render_plan_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(plan) = app.pending_plan.as_ref() else {
        return;
    };
    let active = plan
        .changes
        .iter()
        .enumerate()
        .filter(|(idx, _)| !app.plan_change_skipped(*idx))
        .count();
    let total = plan.changes.len();
    let cursor = app.plan_cursor_clamped();
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ PLAN · goal: {} · {active}/{total} active", plan.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(&format!("  summary: {}", plan.summary), area.width as usize),
        theme::primary(),
    ));
    for (idx, change) in plan.changes.iter().enumerate() {
        let skipped = app.plan_change_skipped(idx);
        let marker = if idx == cursor { ">" } else { " " };
        let toggle = if skipped { "[ ]" } else { "[x]" };
        let style = if skipped {
            theme::muted().add_modifier(Modifier::DIM)
        } else if idx == cursor {
            theme::success().add_modifier(Modifier::BOLD)
        } else {
            theme::success()
        };
        lines.push(Line::styled(
            fit(
                &format!("  {marker} {toggle} {}", change.label()),
                area.width as usize,
            ),
            style,
        ));
    }
    for note in &plan.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    // Mirror the keybind footer's accent-key + muted-hint shape rather
    // than `[k]` chrome.  Per `design/mockups/plan.jsx` and the rest of
    // the shell.  Slash verbs (/yes, /no) are kept as muted hints since
    // they aren't single keys.
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("j/k", theme::accent()),
        Span::raw(" "),
        Span::styled("move", theme::muted()),
        Span::raw("   "),
        Span::styled("space", theme::accent()),
        Span::raw(" "),
        Span::styled("toggle", theme::muted()),
        Span::raw("   "),
        Span::styled("y", theme::accent()),
        Span::raw(" "),
        Span::styled("apply active", theme::muted()),
        Span::raw("   "),
        Span::styled("n", theme::accent()),
        Span::raw(" "),
        Span::styled("discard", theme::muted()),
        Span::raw("   "),
        Span::styled("/yes", theme::muted()),
        Span::raw("   "),
        Span::styled("/no", theme::muted()),
    ]));
    render_lines(frame, area, lines);
}

pub(in crate::renderer) fn render_cost_cap_halt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(halt) = app.advisory.budget_halt.as_ref() else {
        return;
    };
    let header = fit(
        &format!(
            "■ COST CAP HALT · spent ${:.4} / cap ${:.4}",
            halt.spent_usd, halt.limit_usd
        ),
        area.width as usize,
    );
    let mut lines = vec![Line::styled(header, theme::danger())];
    if area.height > 1 {
        // Mirror the unbracketed key style from `keybindings_line` /
        // `design/mockups/_shared.jsx::footer` — accent key + muted hint
        // separated by 3 spaces.  Matches the rest of the shell's
        // muscle-memory rather than re-introducing `[k]` chrome.
        let action_line = Line::from(vec![
            Span::raw(" "),
            Span::styled("c", theme::accent()),
            Span::raw(" "),
            Span::styled("continue past cap", theme::warn()),
            Span::raw("   "),
            Span::styled("a", theme::accent()),
            Span::raw(" "),
            Span::styled("abort scan", theme::warn()),
        ]);
        lines.push(action_line);
    }
    render_lines(frame, area, lines);
}
