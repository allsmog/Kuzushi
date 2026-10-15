use super::*;
use kuzushi_core::run_lifecycle::*;

fn result(message: &str) -> RunPresentationPayloadV1 {
    RunPresentationPayloadV1::ResultSummary(ResultSummaryPresentationV1 {
        tool: SafeText::operator_visible("context:build"),
        status: SafeText::operator_visible("failed"),
        summary: SafeText::operator_visible("Context preparation failed"),
        output_lines: vec![],
        output_line_count: 0,
        warnings: vec![],
        warning_count: 0,
        errors: vec![SafeText::operator_visible(message)],
        error_count: 1,
        artifacts: vec![],
        artifact_count: 0,
    })
}

fn presentation(
    status: Option<RunItemStatus>,
    payloads: Vec<RunPresentationPayloadV1>,
) -> RunPresentationV1 {
    let mut view = present_projection(&RunProjection::default(), RunProjectionSource::TypedV1);
    view.terminal_status = status;
    view.summary = vec![RunPresentationSectionV1 {
        kind: RunPresentationSectionKindV1::Evidence,
        cells: payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| RunPresentationCellV1 {
                key: RunCellKey {
                    source: RunCellSourceV1::ArtifactDigest(SafeText::operator_visible("fixture")),
                    role: RunCellRoleV1::ResultSummary,
                    ordinal: index as u64,
                },
                importance: RunCellImportanceV1::Essential,
                payload,
                disclosure: None,
            })
            .collect(),
    }];
    view
}

#[test]
fn incomplete_runs_promote_recorded_errors_without_rewriting_the_receipt() {
    for status in [
        RunItemStatus::Failed,
        RunItemStatus::Blocked,
        RunItemStatus::Partial,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
    ] {
        let view = presentation(
            Some(status),
            vec![
                result("First error"),
                result("Recorded issue for 資料/my  project"),
            ],
        );
        let original = view.clone();
        let issue = replay_issue(&view).unwrap();
        assert_eq!(issue.label, "Recorded error");
        assert_eq!(issue.message, "Recorded issue for 資料/my  project");
        assert!(issue.tool.unwrap().contains("context"));
        assert_eq!(view, original);
    }
}

#[test]
fn successful_and_active_runs_do_not_promote_historical_errors() {
    for status in [
        None,
        Some(RunItemStatus::Completed),
        Some(RunItemStatus::Skipped),
        Some(RunItemStatus::Pending),
        Some(RunItemStatus::Running),
    ] {
        assert!(replay_issue(&presentation(status, vec![result("Earlier error")])).is_none());
    }
}

#[test]
fn unavailable_evidence_is_named_without_inventing_an_error_from_raw_output() {
    let unavailable =
        RunPresentationPayloadV1::ResultHydrationIssue(ResultHydrationIssuePresentationV1 {
            detail: SafeText::operator_visible("Result digest does not match the saved reference"),
        });
    let view = presentation(Some(RunItemStatus::Failed), vec![unavailable]);
    let issue = replay_issue(&view).unwrap();
    assert_eq!(issue.label, "Evidence unavailable");
    assert!(issue.message.contains("digest"));
    assert_eq!(issue.tool, None);
}

#[test]
fn absent_errors_promote_recorded_warning_without_treating_raw_output_as_an_error() {
    let mut payload = result("  ");
    let RunPresentationPayloadV1::ResultSummary(value) = &mut payload else {
        unreachable!()
    };
    value
        .warnings
        .push(SafeText::operator_visible("Source coverage is partial"));
    value.output_lines.push(SafeText::operator_visible(
        "Raw output is not a typed error",
    ));
    let view = presentation(Some(RunItemStatus::Partial), vec![payload]);
    let original = view.clone();
    let issue = replay_issue(&view).unwrap();
    assert_eq!(issue.label, "Recorded warning");
    assert_eq!(issue.message, "Source coverage is partial");
    assert_eq!(view, original);
    assert!(replay_issue(&presentation(Some(RunItemStatus::Failed), vec![])).is_none());
}

#[test]
fn recorded_errors_outrank_a_later_warning_and_success_promotes_neither() {
    let error = result("Actual recorded error");
    let mut warning = result("");
    let RunPresentationPayloadV1::ResultSummary(value) = &mut warning else {
        unreachable!()
    };
    value
        .warnings
        .push(SafeText::operator_visible("Later warning"));
    let payloads = vec![error, warning];
    let view = presentation(Some(RunItemStatus::Partial), payloads.clone());
    assert_eq!(
        replay_issue(&view).unwrap().message,
        "Actual recorded error"
    );
    assert!(replay_issue(&presentation(Some(RunItemStatus::Completed), payloads)).is_none());
}

#[test]
fn a_warning_does_not_replace_a_failure_or_active_terminal_summary() {
    let mut payload = result("");
    let RunPresentationPayloadV1::ResultSummary(value) = &mut payload else {
        unreachable!()
    };
    value
        .warnings
        .push(SafeText::operator_visible("Earlier warning"));
    for status in [
        RunItemStatus::Failed,
        RunItemStatus::Blocked,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
        RunItemStatus::Completed,
        RunItemStatus::Running,
    ] {
        assert!(replay_issue(&presentation(Some(status), vec![payload.clone()])).is_none());
    }
}
