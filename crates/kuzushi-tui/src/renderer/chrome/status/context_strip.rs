use super::*;
use crate::ui_view_models::{routing_mode_segment, view_status_segment};

pub(crate) fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let target = app
        .target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string());
    let view = view_status_segment(app);
    let model = context_strip_model(app);
    let cost_visible = app.session_cost_usd > 0.0;
    let cost_text = format_session_cost(app.session_cost_usd);

    // Build the cockpit strip:
    //   `KUZUSHI mode:<m> | target <path> | ctx <s> | model <m>`
    // - heading: bold white
    // - segment label: muted
    // - segment value: primary
    // - `✓` ctx checkmark when context snapshot exists: success
    // - view segment mirrors the bottom status view label from `view_status_segment`
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    spans.push(Span::styled("KUZUSHI", theme::heading()));
    spans.push(Span::raw(" "));

    push_prefixed_segment(&mut spans, routing_mode_segment(app), theme::accent());

    push_segment(&mut spans, "target", target.clone(), theme::primary());
    push_context_segment(&mut spans, app.context_view.exists);
    push_segment(&mut spans, "model", model.clone(), theme::primary());
    push_segment(
        &mut spans,
        "findings",
        findings_count_summary(&app.findings),
        theme::primary(),
    );
    push_segment(&mut spans, "view", view.clone(), theme::accent());

    push_activity_or_run_segment(&mut spans, app);

    // stage segment: only when something is running, per
    // `design/mockups/sast-running.jsx::customStrip`:
    //   `stage ⠿ running` (warn-tinted)
    // Includes a spinner frame so the strip animates while the worker
    // ticks.
    push_stage_segment(&mut spans, app);

    push_cost_or_trim(&mut spans, cost_visible, cost_text);

    if spans_overflow(&spans, area.width) {
        return compact_context_strip_line(app, area, target, view, &model, cost_visible);
    }

    vec![Line::from(spans)]
}

fn context_strip_model(app: &ShellApp) -> String {
    app.config
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn spans_overflow(spans: &[Span<'static>], width: u16) -> bool {
    spans
        .iter()
        .map(|span| span.content.chars().count())
        .sum::<usize>()
        + 1
        > width as usize
}

fn compact_context_strip_line(
    app: &ShellApp,
    area: Rect,
    target: String,
    view: String,
    model: &str,
    cost_visible: bool,
) -> Vec<Line<'static>> {
    let compact = compact_context_segments(app, target, view, model, cost_visible);
    let rest = fit(&compact.join(" | "), area.width.saturating_sub(9) as usize);
    vec![Line::from(vec![
        Span::styled("KUZUSHI", theme::heading()),
        Span::raw(" "),
        Span::styled(rest, theme::primary()),
    ])]
}

fn push_prefixed_segment(spans: &mut Vec<Span<'static>>, value: String, style: Style) {
    spans.push(Span::styled(value, style));
    push_separator(spans);
}

fn push_segment(spans: &mut Vec<Span<'static>>, label: &'static str, value: String, style: Style) {
    spans.push(Span::styled(format!("{label} "), theme::muted()));
    spans.push(Span::styled(value, style));
    push_separator(spans);
}

fn push_separator(spans: &mut Vec<Span<'static>>) {
    spans.push(Span::styled(" | ", theme::subtle()));
}

fn push_context_segment(spans: &mut Vec<Span<'static>>, context_exists: bool) {
    spans.push(Span::styled("ctx ", theme::muted()));
    if context_exists {
        spans.push(Span::styled("✓ ", theme::success()));
        spans.push(Span::styled("present", theme::primary()));
    } else {
        spans.push(Span::styled("missing", theme::warn()));
    }
    push_separator(spans);
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
    spans.push(Span::styled("stage ", theme::muted()));
    let frame = SPINNER_FRAMES[(app.spinner_phase as usize) % SPINNER_FRAMES.len()];
    spans.push(Span::styled(format!("{frame} {label}"), theme::warn()));
    push_separator(spans);
}

fn push_cost_or_trim(spans: &mut Vec<Span<'static>>, cost_visible: bool, cost_text: String) {
    if cost_visible {
        push_segment(spans, "cost", cost_text, theme::primary());
    }
    if matches!(spans.last(), Some(span) if span.content == " | ") {
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
        compact_context_state(app.context_view.exists),
        format!("model {model}"),
        findings_count_summary(&app.findings),
        format!("view {view}"),
    ];
    push_compact_activity_and_stage(&mut compact, app);
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
