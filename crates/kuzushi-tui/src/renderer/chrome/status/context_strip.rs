use super::*;
use crate::ui_view_models::{context_strip_model, ContextStripModel, ContextStripSegment};

#[cfg(test)]
#[path = "context_strip/tests.rs"]
mod index_state_tests;

pub(crate) fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = context_strip_model(app);

    // View, target and phase give orientation. The selected model and optional
    // repository index keep their own readiness visible beside that journey.
    let spans = context_strip_spans(&model);

    if spans_overflow(&spans, area.width) {
        return compact_context_strip_lines(&model, area);
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
    push_context_segment(&mut spans, model);
    push_segment(&mut spans, "model", model.model.clone(), theme::primary());
    push_activity_or_run_segment(&mut spans, model);
    push_stage_segment(&mut spans, model.stage.as_ref());
    push_cost_or_trim(&mut spans, model.cost.clone());
    spans
}

fn spans_overflow(spans: &[Span<'static>], width: u16) -> bool {
    spans
        .iter()
        .map(|span| display_width(span.content.as_ref()))
        .sum::<usize>()
        + 1
        > width as usize
}

fn compact_context_strip_lines(model: &ContextStripModel, area: Rect) -> Vec<Line<'static>> {
    if area.height <= 16 {
        return vec![compact_orientation_line(
            &model.compact_segments(),
            area.width,
        )];
    }
    vec![
        compact_orientation_line(&model.orientation_segments(), area.width),
        Line::styled(
            whole_status_segments(&model.status_segments(), usize::from(area.width)),
            theme::muted(),
        ),
    ]
}

fn compact_orientation_line(segments: &[String], columns: u16) -> Line<'static> {
    let width = usize::from(columns);
    let brand = fit("KUZUSHI", width);
    let rest_width = width.saturating_sub(display_width(&brand) + 1);
    let rest = fit(&segments.join(" · "), rest_width);
    let mut spans = vec![Span::styled(brand, theme::heading())];
    if !rest.is_empty() {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(rest, theme::primary()));
    }
    Line::from(spans)
}

fn whole_status_segments(segments: &[String], width: usize) -> String {
    let mut chosen = Vec::new();
    let mut used = 0;
    let mut omitted = false;
    for segment in segments {
        let separator = usize::from(!chosen.is_empty()) * 3;
        let next_width = used + separator + display_width(segment);
        if next_width > width {
            omitted = true;
            continue;
        }
        chosen.push(segment.as_str());
        used = next_width;
    }
    if omitted && used + 4 <= width {
        chosen.push("…");
    }
    chosen.join(" · ")
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

fn push_context_segment(spans: &mut Vec<Span<'static>>, model: &ContextStripModel) {
    let style = if matches!(model.context_state, "malformed" | "unavailable") {
        theme::warn()
    } else {
        theme::muted()
    };
    spans.push(Span::styled(model.context_state_segment(), style));
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
        push_segment(spans, "session", cost, theme::primary());
    }
    if matches!(spans.last(), Some(span) if span.content == " · ") {
        spans.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn line_width(line: &Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum()
    }

    #[test]
    fn detects_overflow_by_terminal_cell_width() {
        assert!(spans_overflow(&[Span::raw("日本")], 4));
        assert!(!spans_overflow(&[Span::raw("日本")], 5));
    }

    #[test]
    fn context_strip_fits_every_width_including_sub_brand_widths() {
        let app = ShellApp::new(V2Config::default(), None);
        for width in 0..=100 {
            let lines = context_strip(&app, Rect::new(0, 0, width, 1));

            assert!(
                lines.iter().all(|line| line_width(line) <= width as usize),
                "context strip exceeded {width}: {lines:?}"
            );
        }
    }
}
