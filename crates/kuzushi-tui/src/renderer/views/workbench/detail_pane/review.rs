//! Review is a source-evidence reader. Historical proof remains evidence;
//! it does not turn the reading path into a verification or patch workflow.
use super::*;

pub(in crate::renderer::views::workbench) fn review_detail_lines(
    detail: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let budget = width.saturating_sub(2).max(16);
    let mut lines = Vec::new();
    push_review_location(&mut lines, detail, budget);
    lines.extend(detail_title_lines(detail, budget));
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

fn push_review_location(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, width: usize) {
    if !detail.location.is_empty() {
        push_literal_line(lines, &detail.location, width, "", theme::muted());
    }
}

#[cfg(test)]
mod literal_header_tests {
    use super::*;

    #[test]
    fn selected_location_precedes_claims_and_mutating_actions_at_every_width() {
        let detail = FindingDetailModel {
            location: "\" app /lib.py\":2".into(),
            title: "The same policy title on two different files".into(),
            ..Default::default()
        };
        for width in [36, 56, 76, 92, 116, 156] {
            let lines = review_detail_lines(&detail, width);
            assert_eq!(lines[0].to_string(), detail.location);
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.find(&detail.location).unwrap() < text.find("REVIEW ACTIONS").unwrap());
        }
    }

    #[test]
    fn moving_the_location_keeps_source_reading_free_of_a_duplicate_path_row() {
        let detail = FindingDetailModel {
            location: "\" app /lib.py\":2".into(),
            source_snippet: Some(crate::ui_view_models::SourceSnippetModel {
                start_line: 1,
                focus_line: 2,
                lines: vec!["// owned source".into(), "// selected source line".into()],
                note: None,
            }),
            ..Default::default()
        };
        let text = review_detail_lines(&detail, 76)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let before_actions = text.split("REVIEW ACTIONS").next().unwrap();
        assert_eq!(before_actions.matches(&detail.location).count(), 1);
        assert!(before_actions.contains("selected source line"));
    }
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
    push_observation_reference(lines, detail, width);
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

fn push_observation_reference(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    width: usize,
) {
    let Some(reference) = &detail.observation_reference else {
        return;
    };
    push_wrapped(
        lines,
        &format!("Reopen this observation: open {reference}"),
        width,
        "  ",
        theme::accent(),
    );
    push_wrapped(
        lines,
        "This reference belongs to this workspace. List aliases can change as findings arrive.",
        width,
        "  ",
        theme::muted(),
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
    fn exact_observation_command_is_readable_at_every_supported_width() {
        let mut detail = super::super::tests::detail();
        detail.observation_reference = Some("generation:9223372036854775807".into());
        for width in [36, 56, 76, 92, 116, 156] {
            let lines = review_detail_lines(&detail, width);
            assert!(lines.iter().all(|line| line.width() <= width));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                words.contains("open generation:9223372036854775807"),
                "{width}: {text}"
            );
            assert!(words.contains("This reference belongs to this workspace."));
            assert!(words.contains("List aliases can change as findings arrive."));
        }
    }

    #[test]
    fn unpersisted_observation_has_no_reopen_promise() {
        let detail = super::super::tests::detail();
        let text = review_detail_lines(&detail, 116)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains("Reopen this observation"));
        assert!(!text.contains("This reference belongs"));
    }

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
