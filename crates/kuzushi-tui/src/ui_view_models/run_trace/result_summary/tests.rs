use super::*;

fn model() -> ReplayModel {
    let mut presentation =
        present_projection(&RunProjection::default(), RunProjectionSource::TypedV1);
    presentation.terminal_status = Some(RunItemStatus::Completed);
    presentation.summary = vec![RunPresentationSectionV1 {
        kind: RunPresentationSectionKindV1::Evidence,
        cells: vec![RunPresentationCellV1 {
            key: RunCellKey {
                source: RunCellSourceV1::Item(RunItemId::new()),
                role: RunCellRoleV1::ResultSummary,
                ordinal: 0,
            },
            importance: RunCellImportanceV1::Essential,
            payload: RunPresentationPayloadV1::ResultSummary(ResultSummaryPresentationV1 {
                tool: SafeText::operator_visible("context:check"),
                status: SafeText::operator_visible("completed"),
                summary: SafeText::operator_visible("Owned context"),
                output_lines: vec![SafeText::operator_visible("Saved source context")],
                output_line_count: 40,
                warnings: Vec::new(),
                warning_count: 0,
                errors: Vec::new(),
                error_count: 0,
                artifacts: Vec::new(),
                artifact_count: 0,
            }),
            disclosure: Some(RunCellDisclosureV1 {
                reason: SafeText::operator_visible("More output in saved artifact"),
                omitted_count: Some(39),
                inspect_action: None,
            }),
        }],
    }];
    ReplayModel {
        run_id: "owned-single-result".into(),
        presentation: Some(presentation),
        projection_error: None,
        artifacts: Vec::new(),
        metadata_missing: false,
        issue: None,
        document: None,
        single_result_work: true,
    }
}

#[test]
fn healthy_single_result_is_readable_without_mutating_or_erasing_disclosures() {
    let model = model();
    let before = model.clone();
    let summary = replay_summary(&model).unwrap();
    let text = summary
        .summary_text_rows()
        .iter()
        .map(|row| row.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Saved source context") && text.contains("omitted=39"));
    assert_eq!(model, before);
    assert!(replay_document_available(&model));
}

#[test]
fn compound_or_mismatched_or_missing_results_keep_full_receipt() {
    let mut model = model();
    let cell = model.presentation.as_ref().unwrap().summary[0].cells[0].clone();
    model.presentation.as_mut().unwrap().summary[0]
        .cells
        .push(cell);
    assert!(!replay_summary_available(&model));
    model.presentation.as_mut().unwrap().summary[0].cells.pop();
    model.presentation.as_mut().unwrap().terminal_status = Some(RunItemStatus::Partial);
    assert!(!replay_summary_available(&model));
    model.presentation.as_mut().unwrap().summary.clear();
    assert!(!replay_summary_available(&model));
}

#[test]
fn unavailable_or_uncertain_evidence_cannot_enable_the_focused_result() {
    let mut missing = model();
    missing.metadata_missing = true;
    assert!(!replay_summary_available(&missing));
    let mut unavailable = model();
    unavailable.projection_error = Some("Unavailable".into());
    assert!(!replay_summary_available(&unavailable));
    let mut stale = model();
    stale.presentation.as_mut().unwrap().health.integrity = ProjectionHealth::Degraded {
        valid_through_seq: 1,
        reason: "Owned stream gap".into(),
    };
    assert!(!replay_summary_available(&stale));
}

#[test]
fn a_second_unavailable_result_cannot_hide_behind_one_successful_result() {
    let mut model = model();
    let mut cell = model.presentation.as_ref().unwrap().summary[0].cells[0].clone();
    cell.payload =
        RunPresentationPayloadV1::ResultHydrationIssue(ResultHydrationIssuePresentationV1 {
            detail: SafeText::operator_visible("Owned second result unavailable"),
        });
    model.presentation.as_mut().unwrap().summary[0]
        .cells
        .push(cell);
    assert!(!replay_summary_available(&model));
    assert!(!replay_document_available(&model));
}

#[test]
fn metadata_only_success_keeps_full_receipt_instead_of_an_empty_saved_output() {
    let mut model = model();
    let RunPresentationPayloadV1::ResultSummary(result) =
        &mut model.presentation.as_mut().unwrap().summary[0].cells[0].payload
    else {
        unreachable!()
    };
    result.output_lines.clear();
    result.output_line_count = 0;
    assert!(!replay_summary_available(&model));
}

#[test]
fn stopped_results_remain_readable_when_only_progress_updates_were_omitted() {
    for status in [
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
        RunItemStatus::Blocked,
        RunItemStatus::Skipped,
    ] {
        let mut model = model();
        let source = model.presentation.as_mut().unwrap();
        source.terminal_status = Some(status);
        source.health.progress = RunProgressFidelity::Coalesced { omitted: 7 };
        let RunPresentationPayloadV1::ResultSummary(result) =
            &mut source.summary[0].cells[0].payload
        else {
            unreachable!()
        };
        result.status = SafeText::operator_visible(status.label());
        let before = model.clone();
        assert!(replay_document_available(&model), "{status:?}");
        assert!(replay_summary_available(&model));
        assert_eq!(model, before);
        assert!(!super::super::replay_can_lead_with_results(
            model.presentation.as_ref().unwrap()
        ));
    }
}

#[test]
fn omitted_progress_does_not_admit_a_running_or_mismatched_result() {
    let mut model = model();
    let source = model.presentation.as_mut().unwrap();
    source.health.progress = RunProgressFidelity::Saturated {
        omitted_at_least: 7,
    };
    source.terminal_status = Some(RunItemStatus::Running);
    assert!(!replay_document_available(&model));
    model.presentation.as_mut().unwrap().terminal_status = Some(RunItemStatus::Failed);
    assert!(!replay_document_available(&model));
}
