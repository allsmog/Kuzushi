use super::*;
use crate::ui_view_models::{context_strip_model, ContextStripModel, ContextStripSegment};

pub(crate) fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = context_strip_model(app);

    // Build the cockpit strip:
    //   `KUZUSHI › <view> · mode:<m> · target:<path> · phase:<p> · ctx:<s> · model:<m>`
    // View/target/phase are the stable breadcrumb; model and context keep
    // runtime safety and optional repo-index state visible without opening
    // another panel.
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
    push_breadcrumb_segment(&mut spans, model.view.clone());
    push_prefixed_segment(&mut spans, model.mode.clone(), theme::accent());
    push_segment(&mut spans, "target", model.target.clone(), theme::primary());
    if let Some(phase) = &model.phase {
        push_segment(&mut spans, "phase", phase.clone(), theme::accent());
    }
    push_context_segment(&mut spans, model.context_state);
    push_segment(&mut spans, "model", model.model.clone(), theme::primary());
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
        &model.compact_segments().join(" · "),
        area.width.saturating_sub(9) as usize,
    );
    vec![Line::from(vec![
        Span::styled("KUZUSHI", theme::heading()),
        Span::raw(" "),
        Span::styled(rest, theme::primary()),
    ])]
}

fn push_breadcrumb_segment(spans: &mut Vec<Span<'static>>, view: String) {
    spans.push(Span::styled("› ", theme::subtle()));
    spans.push(Span::styled(view, theme::accent()));
    push_separator(spans);
}

fn push_prefixed_segment(spans: &mut Vec<Span<'static>>, value: String, style: Style) {
    spans.push(Span::styled(value, style));
    push_separator(spans);
}

fn push_segment(spans: &mut Vec<Span<'static>>, label: &'static str, value: String, style: Style) {
    spans.push(Span::styled(format!("{label}:"), theme::muted()));
    spans.push(Span::styled(value, style));
    push_separator(spans);
}

fn push_separator(spans: &mut Vec<Span<'static>>) {
    spans.push(Span::styled(" · ", theme::subtle()));
}

fn push_context_segment(spans: &mut Vec<Span<'static>>, context_state: &'static str) {
    spans.push(Span::styled("ctx:", theme::muted()));
    match context_state {
        "present" => {
            spans.push(Span::styled("✓ ", theme::success()));
            spans.push(Span::styled("built", theme::primary()));
        }
        // Only a malformed snapshot is a real problem (warn). "Not built" is a
        // normal optional state — keep it muted so it doesn't read as an error.
        "malformed" => spans.push(Span::styled("malformed", theme::warn())),
        _ => spans.push(Span::styled("not built", theme::muted())),
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
    if matches!(spans.last(), Some(span) if span.content == " · ") {
        spans.pop();
    }
}
