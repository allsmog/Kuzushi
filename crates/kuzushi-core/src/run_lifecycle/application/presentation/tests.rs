use super::*;
use crate::run_lifecycle::{OperationFingerprint, RunItemSource};

#[test]
fn semantic_keys_are_stable_and_progress_loss_is_disclosed() {
    let run_id = RunId::parse("run-presentation-disclosure").unwrap();
    let item_id = RunItemId::new();
    let progress = envelope(
        1,
        &run_id,
        item_id,
        RunItemV1::ProgressTruncated {
            progress_item_id: item_id,
            omitted_count: 17,
        },
        None,
    );
    let projection = super::super::reduce_run_items([progress]);
    let first = present_projection(&projection, RunProjectionSource::TypedV1);
    let second = present_projection(&projection, RunProjectionSource::TypedV1);
    assert_eq!(first.semantic_keys(), second.semantic_keys());
    assert_eq!(
        first.timeline[0].disclosure.as_ref().unwrap().omitted_count,
        Some(17)
    );
}

#[test]
fn typed_timeline_reads_as_actions_instead_of_protocol_records() {
    let run_id = RunId::parse("run-readable-timeline").unwrap();
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let requested = requested_item(&run_id, item_id).with_call(call_id).unwrap();
    let started = started_item(&run_id, item_id, &requested)
        .with_call(call_id)
        .unwrap();
    let progress = envelope(
        3,
        &run_id,
        item_id,
        RunItemV1::ToolCallProgress {
            message: SafeText::operator_visible("Scanning repository files"),
            completed: Some(421),
            total: Some(832),
        },
        Some(&started),
    )
    .with_call(call_id)
    .unwrap();
    let finished = envelope(
        4,
        &run_id,
        item_id,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: RuntimeCostReport::UNAVAILABLE,
            result_artifact: None,
            preview: vec![SafeText::preview_line("7 findings")],
            warning_count: 0,
            error_count: 0,
        },
        Some(&progress),
    )
    .with_call(call_id)
    .unwrap();
    let projection = super::super::reduce_run_items([requested, started, progress, finished]);
    let lines = present_projection(&projection, RunProjectionSource::TypedV1)
        .timeline_text_rows()
        .into_iter()
        .map(|row| row.text)
        .collect::<Vec<_>>();

    assert!(lines.iter().any(|line| line.contains("Semgrep") && line.contains("started")));
    assert!(lines
        .iter()
        .any(|line| line.contains("Scanning repository files · 421/832")));
    assert!(lines
        .iter()
        .any(|line| line.contains("completed") && line.contains("7 findings")));
    assert!(!lines.iter().any(|line| line.contains("Call ")));
    assert!(!lines.iter().any(|line| line.contains('%')));
}

#[test]
fn verified_result_is_keyed_by_digest_and_discloses_omissions() {
    let run_id = RunId::parse("run-presentation-result").unwrap();
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let items = tool_call_items(&run_id, item_id, call_id);
    let projection = super::super::reduce_run_items(items);
    let mut hydration = RunPresentationHydrationV1::default();
    hydration.insert_verified(item_id, result_summary(&run_id));
    let presentation =
        present_projection_with_hydration(&projection, RunProjectionSource::TypedV1, &hydration);
    let cell = find_result_cell(&presentation);
    assert_eq!(
        cell.key.source,
        RunCellSourceV1::ArtifactDigest(SafeText::operator_visible("sha256:fixture"))
    );
    assert_eq!(cell.disclosure.as_ref().unwrap().omitted_count, Some(2));
}

/// Single-line tool outputs are routinely the summary restated; the preview
/// row must not echo the heading verbatim while distinct lines still show.
#[test]
fn result_display_skips_the_preview_line_that_restates_the_summary() {
    let run_id = RunId::parse("run-presentation-echo").unwrap();
    let mut summary = result_summary(&run_id);
    summary.output_lines = vec![
        "bounded evidence".to_string(),
        "Saved: report".to_string(),
    ];
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let projection = super::super::reduce_run_items(tool_call_items(&run_id, item_id, call_id));
    let mut hydration = RunPresentationHydrationV1::default();
    hydration.insert_verified(item_id, summary);
    let presentation =
        present_projection_with_hydration(&projection, RunProjectionSource::TypedV1, &hydration);

    let lines = find_result_cell(&presentation).display_lines();

    assert!(lines[0].contains("bounded evidence"), "heading: {lines:?}");
    assert!(
        !lines[1..].iter().any(|line| line.contains("bounded evidence")),
        "summary echoed below the heading: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("Saved: report")),
        "distinct preview line lost: {lines:?}"
    );
}

#[test]
fn resolved_question_keeps_projection_truth_without_repeating_actionable_copy() {
    let fixture = question_fixture(true);
    let question = fixture
        .projection
        .questions
        .get(&fixture.question_id)
        .expect("projected question");
    assert_eq!(question.prompt.as_str(), "Choose the scan scope.");
    assert_eq!(question.choices[0].label.as_str(), "Changed files");
    assert!(question.decision.is_some());

    let presented = presented_question(&fixture.presentation);
    assert_eq!(presented.state, QuestionPresentationStateV1::Resolved);
    assert_eq!(presented.prompt, None);
    assert!(presented.choices.is_empty());
    let rendered = fixture.presentation.summary_text_rows();
    assert!(rendered.iter().any(|row| row.text.contains("resolved")));
    assert!(!rendered.iter().any(
        |row| row.text.contains("Choose the scan scope.") || row.text.contains("Changed files")
    ));
}

#[test]
fn outstanding_question_keeps_actionable_prompt_and_choices() {
    let fixture = question_fixture(false);
    let presented = presented_question(&fixture.presentation);

    assert_eq!(
        presented.state,
        QuestionPresentationStateV1::AwaitingDecision
    );
    assert_eq!(
        presented.prompt.as_ref().map(SafeText::as_str),
        Some("Choose the scan scope.")
    );
    assert_eq!(presented.choices[0].label.as_str(), "Changed files");
    assert!(fixture
        .presentation
        .summary_text_rows()
        .iter()
        .any(
            |row| row.text.contains("Choose the scan scope.") && row.text.contains("Changed files")
        ));
}

#[test]
fn degraded_integrity_quarantines_completed_and_skipped_presentations() {
    for status in [RunItemStatus::Completed, RunItemStatus::Skipped] {
        let projection = terminal_projection(status);
        let mut health = projection.lifecycle_health();
        health.integrity = ProjectionHealth::Degraded {
            valid_through_seq: projection.last_committed_seq,
            reason: "corrupt tail".to_string(),
        };

        let presentation = present_projection_with_hydration_and_health(
            &projection,
            RunProjectionSource::TypedV1,
            &RunPresentationHydrationV1::default(),
            health,
        );

        assert_quarantined_completion(&projection, &presentation, status);
    }
}

#[test]
fn failed_durability_quarantines_completion_without_mutating_projection() {
    let projection = terminal_projection(RunItemStatus::Completed);
    let mut health = projection.lifecycle_health();
    health.durability = RunDurabilityHealth::Failed {
        last_durable_seq: projection.last_committed_seq,
        stage: crate::run_lifecycle::PersistenceFailureStage::Sync,
        detail: SafeText::operator_visible("fixture sync failure"),
        execution_may_have_occurred: true,
    };

    let presentation = present_projection_with_hydration_and_health(
        &projection,
        RunProjectionSource::TypedV1,
        &RunPresentationHydrationV1::default(),
        health,
    );

    assert_quarantined_completion(&projection, &presentation, RunItemStatus::Completed);
}

fn assert_quarantined_completion(
    projection: &RunProjection,
    presentation: &RunPresentationV1,
    recorded_status: RunItemStatus,
) {
    assert_eq!(
        projection.terminal.as_ref().unwrap().status,
        recorded_status
    );
    assert_eq!(projection.plan.as_ref().unwrap().status, recorded_status);
    assert_eq!(
        projection.phase_receipt.as_ref().unwrap().status,
        recorded_status
    );
    assert_eq!(presentation.terminal_status, Some(RunItemStatus::Partial));
    assert_quarantined_payloads(presentation);
    assert_quarantined_text(presentation);
    let healthy = present_projection(projection, RunProjectionSource::TypedV1);
    assert_eq!(presentation.semantic_keys(), healthy.semantic_keys());
}

fn assert_quarantined_payloads(presentation: &RunPresentationV1) {
    let payloads = presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells);
    for payload in payloads.map(|cell| &cell.payload) {
        match payload {
            RunPresentationPayloadV1::Plan(plan) => assert_eq!(plan.status, RunItemStatus::Partial),
            RunPresentationPayloadV1::Terminal(terminal) => {
                assert_eq!(terminal.status, RunItemStatus::Partial);
                assert!(matches!(
                    terminal.continuation,
                    WorkflowContinuation::InspectRun { .. }
                ));
            }
            RunPresentationPayloadV1::PhaseReceipt(receipt) => {
                assert_eq!(receipt.status, RunItemStatus::Partial);
                assert!(matches!(
                    receipt.continuation,
                    WorkflowContinuation::InspectRun { .. }
                ));
                assert_eq!(receipt.offered_actions.len(), 1);
                assert!(matches!(
                    receipt.offered_actions[0],
                    WorkflowContinuation::InspectRun { .. }
                ));
            }
            _ => {}
        }
    }
}

fn assert_quarantined_text(presentation: &RunPresentationV1) {
    let rows = presentation.summary_text_rows();
    for forbidden in [
        "Plan r1 · completed",
        "Plan r1 · skipped",
        "Outcome · completed",
        "Outcome · skipped",
        "Receipt · completed",
        "Receipt · skipped",
        "NEXT · open Report",
    ] {
        assert!(
            !rows.iter().any(|row| row.text.contains(forbidden)),
            "{forbidden}"
        );
    }
    assert!(rows.iter().any(|row| row.text.contains("quarantined")));
    assert!(rows.iter().any(|row| row.text.contains("NEXT · inspect")));
}

fn terminal_projection(status: RunItemStatus) -> RunProjection {
    let run_id = RunId::parse(&format!("run-quarantined-{}", status.label())).unwrap();
    let plan_id = RunItemId::new();
    let terminal_id = RunItemId::new();
    let receipt_id = RunItemId::new();
    let plan = envelope(
        1,
        &run_id,
        plan_id,
        RunItemV1::PlanUpdated {
            revision: 1,
            title: SafeText::operator_visible("Map target"),
            status: RunItemStatus::Running,
            task_ids: Vec::new(),
        },
        None,
    );
    let terminal = terminal_envelope(&run_id, terminal_id, status, &plan);
    let receipt = receipt_envelope(&run_id, receipt_id, status, &terminal);
    super::super::reduce_run_items([plan, terminal, receipt])
}

fn terminal_envelope(
    run_id: &RunId,
    item_id: RunItemId,
    status: RunItemStatus,
    previous: &RunItemEnvelopeV1,
) -> RunItemEnvelopeV1 {
    envelope(
        2,
        run_id,
        item_id,
        RunItemV1::TerminalOutcome {
            status,
            summary: SafeText::operator_visible("recorded terminal summary"),
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            continuation: WorkflowContinuation::OpenReport {
                reason: SafeText::operator_visible("recorded completion"),
            },
        },
        Some(previous),
    )
}

fn receipt_envelope(
    run_id: &RunId,
    item_id: RunItemId,
    status: RunItemStatus,
    previous: &RunItemEnvelopeV1,
) -> RunItemEnvelopeV1 {
    let advance = WorkflowContinuation::OpenReport {
        reason: SafeText::operator_visible("recorded completion"),
    };
    envelope(
        3,
        run_id,
        item_id,
        RunItemV1::PhaseReceipt {
            run_ids: vec![run_id.clone()],
            status,
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            finding_delta: FindingDeltaSummary {
                added: 0,
                updated: 0,
                removed: 0,
                store_watermark: SafeText::operator_visible("fixture-watermark"),
                finding_id_samples: Vec::new(),
            },
            artifact_ids: Vec::new(),
            interaction_count: 0,
            offered_actions: vec![advance.clone()],
            continuation: advance,
        },
        Some(previous),
    )
}

struct QuestionFixture {
    question_id: RunQuestionId,
    projection: RunProjection,
    presentation: RunPresentationV1,
}

fn question_fixture(resolved: bool) -> QuestionFixture {
    let run_id = RunId::parse("run-question-presentation").unwrap();
    let question_id = RunQuestionId::new();
    let item_id = RunItemId::new();
    let question = question_envelope(&run_id, item_id, question_id);
    let mut items = vec![question.clone()];
    if resolved {
        items.push(decision_envelope(&run_id, item_id, question_id, &question));
    }
    let projection = super::super::reduce_run_items(items);
    let presentation = present_projection(&projection, RunProjectionSource::TypedV1);
    QuestionFixture {
        question_id,
        projection,
        presentation,
    }
}

fn question_envelope(
    run_id: &RunId,
    item_id: RunItemId,
    question_id: RunQuestionId,
) -> RunItemEnvelopeV1 {
    envelope(
        1,
        run_id,
        item_id,
        RunItemV1::OperatorQuestion {
            question_id,
            prompt: SafeText::operator_visible("Choose the scan scope."),
            choices: vec![OperatorChoice {
                id: SafeText::operator_visible("choice-scope-0"),
                label: SafeText::operator_visible("Changed files"),
            }],
            authorization_scope: SafeText::operator_visible("scan scope"),
        },
        None,
    )
}

fn decision_envelope(
    run_id: &RunId,
    item_id: RunItemId,
    question_id: RunQuestionId,
    previous: &RunItemEnvelopeV1,
) -> RunItemEnvelopeV1 {
    envelope(
        2,
        run_id,
        item_id,
        RunItemV1::OperatorDecision {
            question_id,
            decision: OperatorDecisionValue::Selected {
                choice_id: SafeText::operator_visible("choice-scope-0"),
            },
            authorization_scope: SafeText::operator_visible("scan scope"),
        },
        Some(previous),
    )
}

fn presented_question(presentation: &RunPresentationV1) -> &QuestionPresentationV1 {
    presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .find_map(|cell| match &cell.payload {
            RunPresentationPayloadV1::Question(question) => Some(question),
            _ => None,
        })
        .expect("presented question")
}

fn tool_call_items(
    run_id: &RunId,
    item_id: RunItemId,
    call_id: RunCallId,
) -> Vec<RunItemEnvelopeV1> {
    let requested = requested_item(run_id, item_id).with_call(call_id).unwrap();
    let started = started_item(run_id, item_id, &requested)
        .with_call(call_id)
        .unwrap();
    let finished = finished_item(run_id, item_id, &started)
        .with_call(call_id)
        .unwrap();
    vec![requested, started, finished]
}

fn requested_item(run_id: &RunId, item_id: RunItemId) -> RunItemEnvelopeV1 {
    envelope(
        1,
        run_id,
        item_id,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("semgrep:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"present"),
            safe_option_names: Vec::new(),
        },
        None,
    )
}

fn started_item(
    run_id: &RunId,
    item_id: RunItemId,
    previous: &RunItemEnvelopeV1,
) -> RunItemEnvelopeV1 {
    envelope(
        2,
        run_id,
        item_id,
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("semgrep:scan"),
            runtime: Some(SafeText::operator_visible("agent")),
            model: Some(SafeText::operator_visible("model-x")),
        },
        Some(previous),
    )
}

fn finished_item(
    run_id: &RunId,
    item_id: RunItemId,
    previous: &RunItemEnvelopeV1,
) -> RunItemEnvelopeV1 {
    envelope(
        3,
        run_id,
        item_id,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Partial,
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            result_artifact: Some(result_reference(item_id)),
            preview: vec![SafeText::preview_line("one"), SafeText::preview_line("two")],
            warning_count: 1,
            error_count: 0,
        },
        Some(previous),
    )
}

fn result_reference(item_id: RunItemId) -> ArtifactReference {
    ArtifactReference {
        path: SafeText::operator_visible("result.json"),
        kind: SafeText::operator_visible("json"),
        label: SafeText::operator_visible("tool result"),
        digest: SafeText::operator_visible("sha256:fixture"),
        byte_count: 128,
        line_count: Some(4),
        producing_item_id: item_id,
    }
}

fn result_summary(run_id: &RunId) -> crate::run_artifacts::RunResultSummary {
    crate::run_artifacts::RunResultSummary {
        run_id: run_id.to_string(),
        tool: "semgrep:scan".to_string(),
        status: "partial".to_string(),
        summary: "bounded evidence".to_string(),
        output_lines: vec!["Findings: 2".to_string(), "Saved: report".to_string()],
        output_line_count: 4,
        warnings: Vec::new(),
        warning_count: 0,
        errors: Vec::new(),
        error_count: 0,
        artifacts: Vec::new(),
        artifact_count: 0,
    }
}

fn find_result_cell(presentation: &RunPresentationV1) -> &RunPresentationCellV1 {
    presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .find(|cell| matches!(cell.payload, RunPresentationPayloadV1::ResultSummary(_)))
        .expect("result cell")
}

fn envelope(
    seq: u64,
    run_id: &RunId,
    item_id: RunItemId,
    item: RunItemV1,
    previous: Option<&RunItemEnvelopeV1>,
) -> RunItemEnvelopeV1 {
    RunItemEnvelopeV1::new(
        seq,
        run_id.clone(),
        item_id,
        RunItemSource::Dispatch,
        item,
        previous.map(|item| item.event_hash.clone()),
    )
    .unwrap()
}
