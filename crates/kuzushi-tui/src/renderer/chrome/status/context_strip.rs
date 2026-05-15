use super::*;
use crate::ui_view_models::{context_strip_model, ContextStripModel, ContextStripSegment};

pub(crate) fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = context_strip_model(app);

    // Build the cockpit strip:
    //   `KUZUSHI mode:<m> | target <path> | ctx <s> | model <m>`
    // - heading: bold white
    // - segment label: muted
    // - segment value: primary
    // - `✓` ctx checkmark when context snapshot exists: success
    // - view segment mirrors the bottom status view label from `view_status_segment`
    let spans = context_strip_spans(&model);

    if spans_overflow(&spans, area.width) {
        return compact_context_strip_line(&model, area);
    }

    vec![Line::from(spans)]
}

fn context_strip_spans(model: &ContextStripModel) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = vec![
        Span::raw(" "),
        Span::styled("KUZUSHI", theme::heading()),
        Span::raw(" "),
    ];
    push_prefixed_segment(&mut spans, model.mode.clone(), theme::accent());
    push_segment(&mut spans, "target", model.target.clone(), theme::primary());
    push_context_segment(&mut spans, model.context_present);
    push_segment(&mut spans, "model", model.model.clone(), theme::primary());
    push_segment(
        &mut spans,
        "findings",
        model.findings.clone(),
        theme::primary(),
    );
    push_segment(&mut spans, "view", model.view.clone(), theme::accent());
    push_activity_or_run_segment(&mut spans, model);
    push_stage_segment(&mut spans, model.stage.as_ref());
    push_cost_or_trim(&mut spans, model.cost.clone());
    spans
}

fn spans_overflow(spans: &[Span<'static>], width: u16) -> bool {
    spans
        .iter()
        .map(|span| span.content.chars().count())
        .sum::<usize>()
        + 1
        > width as usize
}

fn compact_context_strip_line(model: &ContextStripModel, area: Rect) -> Vec<Line<'static>> {
    let rest = fit(
        &model.compact_segments().join(" | "),
        area.width.saturating_sub(9) as usize,
    );
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

fn push_activity_or_run_segment(spans: &mut Vec<Span<'static>>, model: &ContextStripModel) {
    if let Some(activity) = &model.activity {
        push_status_segment(spans, activity);
        return;
    }
    if let Some(run) = &model.run {
        push_status_segment(spans, run);
    }
}

fn push_status_segment(spans: &mut Vec<Span<'static>>, segment: &ContextStripSegment) {
    push_segment(spans, segment.label, segment.value.clone(), theme::warn());
}

fn push_stage_segment(spans: &mut Vec<Span<'static>>, stage: Option<&ContextStripSegment>) {
    if let Some(stage) = stage {
        push_status_segment(spans, stage);
    }
}

fn push_cost_or_trim(spans: &mut Vec<Span<'static>>, cost: Option<String>) {
    if let Some(cost) = cost {
        push_segment(spans, "cost", cost, theme::primary());
    }
    if matches!(spans.last(), Some(span) if span.content == " | ") {
        spans.pop();
    }
}
