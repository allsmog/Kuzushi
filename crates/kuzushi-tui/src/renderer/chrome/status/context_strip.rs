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

    let push_segment =
        |spans: &mut Vec<Span<'static>>, label: &'static str, value: String, style: Style| {
            spans.push(Span::styled(format!("{label} "), theme::muted()));
            spans.push(Span::styled(value, style));
            spans.push(Span::raw("  "));
        };

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

    // ctx
    spans.push(Span::styled("ctx ", theme::muted()));
    if app.context_view.exists {
        spans.push(Span::styled("✓ ", theme::success()));
        spans.push(Span::styled("present", theme::primary()));
    } else {
        spans.push(Span::styled("missing", theme::warn()));
    }
    spans.push(Span::raw("  "));

    // view
    push_segment(&mut spans, "view", view.clone(), theme::accent());

    if let Some(tool_name) = app.running_tool_name() {
        push_segment(
            &mut spans,
            "run",
            format!("{} {tool_name}", app.spinner_glyph()),
            theme::warn(),
        );
    }

    // model
    push_segment(&mut spans, "model", model.to_string(), theme::primary());

    // stage segment: only when something is running, per
    // `design/mockups/sast-running.jsx::customStrip`:
    //   `stage ⠿ running` (warn-tinted)
    // Includes a spinner frame so the strip animates while the worker
    // ticks.
    let stage_label = active_stage_label(app);
    if let Some(label) = stage_label {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("stage ", theme::muted()));
        let frame = SPINNER_FRAMES[(app.spinner_phase as usize) % SPINNER_FRAMES.len()];
        spans.push(Span::styled(format!("{frame} "), theme::warn()));
        spans.push(Span::styled(label.to_string(), theme::warn()));
    }

    if cost_visible {
        spans.push(Span::styled("cost ", theme::muted()));
        spans.push(Span::styled(cost_text, theme::primary()));
    } else if matches!(spans.last(), Some(span) if span.content == "  ") {
        spans.pop();
    }

    // Width safety: if the multi-span row would exceed the available width,
    // fall back to a single fitted line so right-edge segments don't drop
    // silently off-screen on narrow terminals.
    let total_chars: usize = spans.iter().map(|span| span.content.chars().count()).sum();
    if total_chars + 1 > area.width as usize {
        let mut compact = vec![
            routing_mode_segment(app),
            format!("target {target}"),
            findings_count_summary(&app.findings),
        ];
        if app.context_view.exists {
            compact.push("ctx ✓ present".to_string());
        } else {
            compact.push("ctx missing".to_string());
        }
        compact.push(format!("view {view}"));
        compact.push(format!("model {model}"));
        if cost_visible {
            compact.push(format!(
                "cost {}",
                format_session_cost(app.session_cost_usd)
            ));
        }
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
