use super::*;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    trace: &TraceEvidenceModel,
    state: PhaseRenderState,
) {
    render_lines_pane(
        frame,
        area,
        format!("TRACE · {}", trace.reference),
        lines(trace),
        PhaseSurfaceId::ProveTrace,
        state,
    );
}

/// Keep evidence intact; the shared paragraph owns wrapping and scroll extent.
pub(super) fn lines(trace: &TraceEvidenceModel) -> Vec<Line<'static>> {
    let mut lines = identity_lines(trace);
    if let Some(outcome) = &trace.last_outcome {
        lines.extend(text_lines(outcome, theme::primary()));
    }
    append_path(
        &mut lines,
        "RECORDED PATH",
        &trace.original,
        "no located evidence anchors recorded for this finding",
    );
    append_path(
        &mut lines,
        "RECORDED EXPANSIONS · requested by operator",
        &trace.expanded,
        expansion_empty_hint(trace),
    );
    lines.extend(follow_up_lines(trace));
    lines.extend(text_lines(
        format!("NEXT · {}", trace.next_hint),
        theme::muted(),
    ));
    lines.extend(text_lines(&trace.expand_command, theme::accent()));
    lines
}

fn expansion_empty_hint(trace: &TraceEvidenceModel) -> &'static str {
    if trace.last_outcome.is_some() {
        "no additional hops recorded — see the last expansion and its notes"
    } else {
        "no operator-requested expansion recorded for this finding"
    }
}

fn identity_lines(trace: &TraceEvidenceModel) -> Vec<Line<'static>> {
    let mut lines = text_lines(
        format!(
            "{} · {} · where does this value travel",
            trace.reference, trace.severity
        ),
        theme::heading(),
    );
    if let Some(identity) = &trace.identity {
        lines.extend(text_lines(identity, theme::muted()));
    }
    lines
}

fn append_path(
    lines: &mut Vec<Line<'static>>,
    title: &'static str,
    hops: &[TraceHopModel],
    empty: &str,
) {
    lines.push(Line::styled(title, theme::label()));
    if hops.is_empty() {
        lines.extend(text_lines(format!("  {empty}"), theme::muted()));
    }
    lines.extend(hops.iter().flat_map(hop_lines));
}

fn hop_lines(hop: &TraceHopModel) -> Vec<Line<'static>> {
    let location = if hop.location.is_empty() {
        "location unrecorded"
    } else {
        &hop.location
    };
    let mut lines = text_lines(format!("  ▾ {} — {location}", hop.label), theme::primary());
    if !hop.annotation.is_empty() {
        lines.extend(text_lines(
            format!("      {}", hop.annotation),
            theme::muted(),
        ));
    }
    lines
}

fn follow_up_lines(trace: &TraceEvidenceModel) -> Vec<Line<'static>> {
    let mut lines: Vec<_> = trace
        .open_questions
        .iter()
        .flat_map(|question| text_lines(format!("  ? open: {question}"), theme::warn()))
        .collect();
    if !trace.evidence_deltas.is_empty() {
        lines.push(Line::styled("NEW EVIDENCE", theme::label()));
        lines.extend(
            trace
                .evidence_deltas
                .iter()
                .flat_map(|delta| text_lines(format!("  + {delta}"), theme::primary())),
        );
    }
    lines
}

fn text_lines(text: impl AsRef<str>, style: Style) -> Vec<Line<'static>> {
    text.as_ref()
        .split('\n')
        .map(|line| Line::styled(line.to_string(), style))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_keeps_complete_locations_multiline_evidence_and_commands() {
        let location = format!("src/{}/precise_sink.rs:123", "long_component/".repeat(8));
        let annotation = format!(
            "{}FINAL EVIDENCE\nsecond cited line",
            "observed dataflow ".repeat(20)
        );
        let command = format!(
            "run trace:expand {{\"fingerprint\":\"{}\"}}",
            "f".repeat(80)
        );
        let model = TraceEvidenceModel {
            last_outcome: None,
            reference: "F-0001".into(),
            severity: "HIGH".into(),
            identity: None,
            original: vec![TraceHopModel {
                label: "sink".into(),
                location: location.clone(),
                annotation: annotation.clone(),
            }],
            expanded: vec![],
            open_questions: vec![],
            evidence_deltas: vec![],
            expand_command: command.clone(),
            next_hint: "inspect source".into(),
        };
        let text = lines(&model)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [location, annotation, command] {
            assert!(text.contains(&expected), "{text}");
        }
        assert!(!text.contains('…'));
    }
    #[test]
    fn zero_step_trace_renders_recorded_outcome_instead_of_never_run_guidance() {
        let model = TraceEvidenceModel {
            reference: "F-1".into(),
            severity: "HIGH".into(),
            identity: None,
            original: vec![],
            expanded: vec![],
            last_outcome: Some("Last expansion · 0 new steps · run trace-recorded".into()),
            open_questions: vec!["upstream caller unresolved".into()],
            evidence_deltas: vec!["no intermediary hops found".into()],
            expand_command: "run trace:expand {}".into(),
            next_hint: "resolve the recorded open questions".into(),
        };
        let text = lines(&model)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("0 new steps · run trace-recorded"));
        assert!(text.contains("upstream caller unresolved"));
        assert!(text.contains("no intermediary hops found"));
        assert!(!text.contains("no operator-requested expansion recorded"));
    }
}
