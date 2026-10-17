use super::*;

const ISSUE: &str = "Source changed; inspect 資料/my  project.";

fn model() -> ReplayModel {
    let mut presentation =
        present_projection(&RunProjection::default(), RunProjectionSource::TypedV1);
    presentation.terminal_status = Some(RunItemStatus::Partial);
    let result = ResultSummaryPresentationV1 {
        tool: SafeText::operator_visible("context:build"),
        status: SafeText::operator_visible("partial"),
        summary: SafeText::operator_visible(ISSUE),
        output_lines: vec![
            SafeText::operator_visible(ISSUE),
            SafeText::operator_visible("Read-only context retained."),
        ],
        output_line_count: 3,
        errors: vec![
            SafeText::operator_visible(ISSUE),
            SafeText::operator_visible("Source changed after acceptance."),
        ],
        error_count: 2,
        warnings: vec![SafeText::operator_visible(
            "The second scope is uninspected.",
        )],
        warning_count: 1,
        artifacts: vec![ResultArtifactPresentationV1 {
            label: SafeText::operator_visible("Result"),
            path: SafeText::operator_visible("result.json"),
            kind: SafeText::operator_visible("json"),
        }],
        artifact_count: 1,
    };
    presentation.summary = vec![RunPresentationSectionV1 {
        kind: RunPresentationSectionKindV1::Evidence,
        cells: vec![RunPresentationCellV1 {
            key: RunCellKey {
                source: RunCellSourceV1::Item(RunItemId::new()),
                role: RunCellRoleV1::ResultSummary,
                ordinal: 0,
            },
            importance: RunCellImportanceV1::Essential,
            payload: RunPresentationPayloadV1::ResultSummary(result),
            disclosure: Some(RunCellDisclosureV1 {
                reason: SafeText::operator_visible("Original omitted source detail"),
                omitted_count: Some(1),
                inspect_action: None,
            }),
        }],
    }];
    let source_key = Some(presentation.summary[0].cells[0].key.clone());
    ReplayModel {
        run_id: "owned-summary".into(),
        presentation: Some(presentation),
        projection_error: None,
        artifacts: Vec::new(),
        metadata_missing: false,
        document: None,
        single_result_work: true,
        issue: Some(ReplayIssueModel {
            source_key,
            label: "Recorded warning",
            message: ISSUE.into(),
            tool: Some(kuzushi_core::modules::tool_display_name("context:build")),
        }),
    }
}

#[test]
fn failure_summary_folds_only_the_promoted_message_and_preserves_source_truth() {
    let model = model();
    let original = model.clone();
    let summary = failure_summary(&model).unwrap();
    let text = summary
        .summary_text_rows()
        .into_iter()
        .map(|row| row.text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!text.contains(ISSUE));
    assert!(text.contains("Read-only context retained."));
    assert!(text.contains("Source changed after acceptance."));
    assert!(text.contains("second scope is uninspected"));
    assert!(text.contains("Original omitted source detail") && text.contains("omitted=1"));
    assert!(!text.contains("artifacts:"));
    assert_eq!(
        summary.terminal_status,
        original.presentation.as_ref().unwrap().terminal_status
    );
    assert_eq!(model, original);
}

#[test]
fn another_tools_identical_message_keeps_its_own_attribution() {
    let mut model = model();
    model.issue.as_mut().unwrap().tool = Some("Another tool".into());
    model.issue.as_mut().unwrap().source_key = None;
    let summary = failure_summary(&model).unwrap();
    let text = summary
        .summary_text_rows()
        .into_iter()
        .map(|row| row.text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains(ISSUE));
    assert!(text.contains("Build project context"));
}

#[test]
fn another_events_identical_message_from_the_same_tool_is_not_folded() {
    let mut model = model();
    let section = &mut model.presentation.as_mut().unwrap().summary[0];
    let mut second = section.cells[0].clone();
    second.key.ordinal = 1;
    section.cells.push(second);
    let original = model.clone();
    let summary = failure_summary(&model).unwrap();
    let text = summary
        .summary_text_rows()
        .into_iter()
        .map(|row| row.text)
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        text.matches(ISSUE).count(),
        1,
        "Only the promoted event may fold: {text}"
    );
    assert_eq!(model, original);
}

#[test]
fn uncertain_integrity_keeps_the_full_receipt_instead_of_a_summary() {
    let mut model = model();
    model.presentation.as_mut().unwrap().health.integrity = ProjectionHealth::Degraded {
        valid_through_seq: 1,
        reason: "Owned stream gap".into(),
    };
    assert!(!failure_summary_available(&model));
    assert!(failure_summary(&model).is_none());
    model.projection_error = Some("Projection unavailable".into());
    model.presentation = None;
    assert!(failure_summary(&model).is_none());
}

#[test]
fn runs_without_a_recorded_issue_keep_their_existing_reader() {
    let mut model = model();
    model.issue = None;
    assert!(!failure_summary_available(&model));
    assert!(failure_summary(&model).is_none());
}
