use super::*;

pub(crate) fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let target = app
        .target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string());
    let view = view_status_segment(app);
    let model = app.config.model.as_deref().unwrap_or("unconfigured");
    let cost_visible = app.session_cost_usd > 0.0;
    let cost_text = format_session_cost(app.session_cost_usd);

    // Build the strip as styled spans matching `design/mockups/_shared.jsx::statusStrip`:
    //   ` KUZUSHI  mode <m>  target <path>  findings <n>  ctx <s>  view <v>  model <m>`
    // - heading: bold white
    // - segment label: muted
    // - segment value: primary
    // - `✓` ctx checkmark when context snapshot exists: success
    // - view segment mirrors the bottom status view label from `view_status_segment`
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    spans.push(Span::styled("KUZUSHI", theme::heading()));
    spans.push(Span::raw("  "));

    let mode_segment = routing_mode_segment(app);
    let mode = mode_segment
        .strip_prefix("mode:")
        .unwrap_or(&mode_segment)
        .to_string();
    push_segment(&mut spans, "mode", mode, theme::accent());

    // target
    push_segment(&mut spans, "target", target.clone(), theme::primary());

    // findings
    push_segment(
        &mut spans,
        "findings",
        findings_count_summary(&app.findings),
        theme::primary(),
    );

    push_context_segment(&mut spans, app.context_view.exists);

    // view
    push_segment(&mut spans, "view", view.clone(), theme::accent());

    push_activity_or_run_segment(&mut spans, app);

    // stage segment: only when something is running, per
    // `design/mockups/sast-running.jsx::customStrip`:
    //   `stage ⠿ running` (warn-tinted)
    // Includes a spinner frame so the strip animates while the worker
    // ticks.
    push_stage_segment(&mut spans, app);

    // model
    push_segment(&mut spans, "model", model.to_string(), theme::primary());

    push_cost_or_trim(&mut spans, cost_visible, cost_text);

    // Width safety: if the multi-span row would exceed the available width,
    // fall back to a single fitted line so right-edge segments don't drop
    // silently off-screen on narrow terminals.
    let total_chars: usize = spans.iter().map(|span| span.content.chars().count()).sum();
    if total_chars + 1 > area.width as usize {
        let compact = compact_context_segments(app, target, view, model, cost_visible);
        let rest = fit(
            &join_segments(&compact),
            area.width.saturating_sub(9) as usize,
        );
        return vec![Line::from(vec![
            Span::styled("KUZUSHI", theme::heading()),
            Span::raw("  "),
            Span::styled(rest, theme::primary()),
        ])];
    }

    vec![Line::from(spans)]
}

fn push_segment(spans: &mut Vec<Span<'static>>, label: &'static str, value: String, style: Style) {
    spans.push(Span::styled(format!("{label} "), theme::muted()));
    spans.push(Span::styled(value, style));
    spans.push(Span::raw("  "));
}

fn push_context_segment(spans: &mut Vec<Span<'static>>, context_exists: bool) {
    spans.push(Span::styled("ctx ", theme::muted()));
    if context_exists {
        spans.push(Span::styled("✓ ", theme::success()));
        spans.push(Span::styled("present", theme::primary()));
    } else {
        spans.push(Span::styled("missing", theme::warn()));
    }
    spans.push(Span::raw("  "));
}

fn push_activity_or_run_segment(spans: &mut Vec<Span<'static>>, app: &ShellApp) {
    if let Some(activity) = active_live_activity(app) {
        push_segment(
            spans,
            "activity",
            format!("{} {}", app.spinner_glyph(), activity.short_label()),
            theme::warn(),
        );
        return;
    }
    if let Some(tool_name) = app.running_tool_name() {
        push_segment(
            spans,
            "run",
            format!("{} {tool_name}", app.spinner_glyph()),
            theme::warn(),
        );
    }
}

fn active_live_activity(app: &ShellApp) -> Option<&LiveActivity> {
    app.live_activity
        .as_ref()
        .filter(|activity| activity.phase.active())
}

fn push_stage_segment(spans: &mut Vec<Span<'static>>, app: &ShellApp) {
    let Some(label) = active_stage_label(app) else {
        return;
    };
    spans.push(Span::raw("  "));
    spans.push(Span::styled("stage ", theme::muted()));
    let frame = SPINNER_FRAMES[(app.spinner_phase as usize) % SPINNER_FRAMES.len()];
    spans.push(Span::styled(format!("{frame} "), theme::warn()));
    spans.push(Span::styled(label, theme::warn()));
}

fn push_cost_or_trim(spans: &mut Vec<Span<'static>>, cost_visible: bool, cost_text: String) {
    if cost_visible {
        spans.push(Span::styled("cost ", theme::muted()));
        spans.push(Span::styled(cost_text, theme::primary()));
        return;
    }
    if matches!(spans.last(), Some(span) if span.content == "  ") {
        spans.pop();
    }
}

fn compact_context_segments(
    app: &ShellApp,
    target: String,
    view: String,
    model: &str,
    cost_visible: bool,
) -> Vec<String> {
    let mut compact = vec![
        routing_mode_segment(app),
        format!("target {target}"),
        findings_count_summary(&app.findings),
        compact_context_state(app.context_view.exists),
        format!("view {view}"),
    ];
    push_compact_activity_and_stage(&mut compact, app);
    compact.push(format!("model {model}"));
    if cost_visible {
        compact.push(format!(
            "cost {}",
            format_session_cost(app.session_cost_usd)
        ));
    }
    compact
}

fn compact_context_state(context_exists: bool) -> String {
    if context_exists {
        "ctx ✓ present".to_string()
    } else {
        "ctx missing".to_string()
    }
}

fn push_compact_activity_and_stage(compact: &mut Vec<String>, app: &ShellApp) {
    if let Some(activity) = app.live_activity.as_ref() {
        compact.push(format!("activity {}", activity.short_label()));
    }
    if let Some(label) = active_stage_label(app) {
        let frame = SPINNER_FRAMES[(app.spinner_phase as usize) % SPINNER_FRAMES.len()];
        compact.push(format!("stage {frame} {label}"));
    }
}
