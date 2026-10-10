//! Review is a source-evidence reader. Historical proof remains evidence;
//! it does not turn the reading path into a verification or patch workflow.
use super::*;

pub(in crate::renderer::views::workbench) fn review_detail_lines(
    detail: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let budget = width.saturating_sub(2).max(16);
    let mut lines = detail_title_lines(detail, budget);
    push_observation_gap(&mut lines, detail, budget);
    push_review_decision(&mut lines, detail, budget);
    push_decision_source(&mut lines, detail, budget);
    push_source_section(&mut lines, detail, budget);
    push_evidence_section(
        &mut lines,
        &detail.evidence,
        detail.evidence_overflow,
        budget,
    );
    push_dataflow_section(
        &mut lines,
        &detail.dataflow_evidence,
        detail.dataflow_overflow,
        budget,
    );
    push_review_actions(&mut lines, detail, budget);
    push_review_history(&mut lines, detail, budget);
    push_review_yield_section(&mut lines, detail.review_yield.as_ref(), budget);
    push_message_section(&mut lines, detail, budget);
    push_provenance_section(&mut lines, detail, budget);
    push_decision_source_provenance(&mut lines, detail, budget);
    lines
}

fn push_review_decision(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, width: usize) {
    push_section_header(lines, "DECISION");
    if let Some(current) = &detail.current_decision {
        push_recorded_decision(lines, "recorded", current, width);
    } else {
        push_review_fallback(lines, detail, width);
    }
    if let Some(conflict) = detail.decision_conflict.as_deref() {
        let note = crate::ui_view_models::review_conflicts::review_conflict_detail_label(conflict);
        push_wrapped(
            lines,
            &format!("Conflicting decisions: {note}"),
            width,
            "  ",
            theme::warn(),
        );
    }
}

fn push_review_fallback(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, width: usize) {
    push_detail_kv(lines, "verdict", &detail.decision, width);
    let Some(triage) = &detail.triage else {
        push_detail_kv(lines, "source", &detail.decision_source, width);
        return;
    };
    push_detail_kv(lines, "author", &triage.author, width);
    if triage.author != "human" {
        push_detail_kv(
            lines,
            "author-reported confidence",
            &triage.confidence,
            width,
        );
    }
    push_wrapped(lines, &triage.rationale, width, "  ", theme::muted());
}

fn push_decision_source(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, width: usize) {
    let Some(source) = &detail.decision_basis else {
        return;
    };
    push_section_header(lines, "DECISION SOURCE");
    let style = if source.warning {
        theme::warn()
    } else {
        theme::muted()
    };
    push_wrapped(lines, &source.notice, width, "  ", style);
    for row in &source.rows {
        push_wrapped(lines, row, width, "  ", theme::muted());
    }
}

fn push_decision_source_provenance(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    width: usize,
) {
    let Some(source) = &detail.decision_basis else {
        return;
    };
    for row in &source.provenance {
        push_wrapped(lines, row, width, "  ", theme::muted());
    }
}

fn push_review_actions(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, width: usize) {
    push_section_header(lines, "REVIEW ACTIONS");
    push_wrapped(
        lines,
        "Record a verdict with a reason; earlier decisions remain in history.",
        width,
        "  ",
        theme::muted(),
    );
    push_review_action_lines(lines, width);
    if detail.observation_gap.is_some() {
        push_wrapped(
            lines,
            "Compare scans before reassessing whether the finding still applies.",
            width,
            "  ",
            theme::warn(),
        );
    }
    push_wrapped(
        lines,
        "report · export findings and decisions",
        width,
        "  ",
        theme::accent(),
    );
}

fn push_review_history(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, width: usize) {
    let others = detail
        .decision_history_rows
        .iter()
        .filter(|row| Some(*row) != detail.current_decision.as_ref())
        .collect::<Vec<_>>();
    if others.is_empty() {
        return;
    }
    push_section_header(lines, "OTHER DECISIONS");
    for row in others {
        push_recorded_decision(lines, "recorded", row, width);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_leads_with_evidence_and_records_a_decision_once() {
        let mut detail = super::super::tests::detail();
        detail
            .decision_history_rows
            .push(crate::ui_view_models::DecisionHistoryRow {
                verdict: "confirmed".into(),
                author: "operator".into(),
                created_at: "2026-09-09".into(),
                rationale: "Checked the source boundary".into(),
            });
        detail.current_decision = detail.decision_history_rows.first().cloned();
        for width in [36, 56, 76, 92, 116, 156] {
            let lines = review_detail_lines(&detail, width);
            assert!(lines.iter().all(|line| line.width() <= width));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert_eq!(words.matches("Checked the source boundary").count(), 1);
            assert!(text.find("EVIDENCE").unwrap() < text.find("REVIEW ACTIONS").unwrap());
            for retired in [
                "verify F-0001",
                "before patching",
                "legacy triage",
                "decision score",
                "proof band",
            ] {
                assert!(!text.contains(retired), "{width}: {retired}");
            }
        }
    }
}
