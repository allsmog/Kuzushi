use super::*;
use crate::run_lifecycle::{
    OperatorDecisionValue, QuestionDecisionProjection, QuestionProjection, RunItemSource,
    RunQuestionId, TerminalProjection,
};

fn projection(run_id: RunId, status: RunItemStatus) -> RunProjection {
    let mut projection = RunProjection {
        run_id: Some(run_id),
        ..RunProjection::default()
    };
    projection.terminal = Some(TerminalProjection {
        item_id: RunItemId::new(),
        status,
        summary: SafeText::operator_visible("settled"),
        cost: RuntimeCostReport::UNAVAILABLE,
        continuation: WorkflowContinuation::NoFurtherAction {
            reason: SafeText::operator_visible("await phase receipt"),
        },
    });
    projection
}

fn run_id() -> RunId {
    RunId::parse(&crate::run_artifacts::new_run_id("receipt-test")).unwrap()
}

fn question(question_id: RunQuestionId, decided: bool) -> QuestionProjection {
    QuestionProjection {
        question_id,
        item_id: RunItemId::new(),
        prompt: SafeText::operator_visible("Scope?"),
        choices: Vec::new(),
        authorization_scope: SafeText::operator_visible("run"),
        source: RunItemSource::Runtime,
        occurred_at_ms: 1,
        decision: decided.then(decision),
    }
}

fn decision() -> QuestionDecisionProjection {
    QuestionDecisionProjection {
        item_id: RunItemId::new(),
        occurred_at_ms: 2,
        source: RunItemSource::Operator,
        authorization_scope: SafeText::operator_visible("run"),
        value: OperatorDecisionValue::ProvidedFreeform,
    }
}

fn build(run_id: &RunId, projection: &RunProjection) -> Result<RunItemV1> {
    PhaseReceiptBuilder::new(
        WorkflowPhase::Scan,
        RunItemStatus::Completed,
        std::slice::from_ref(run_id),
        std::slice::from_ref(projection),
    )
    .build()
}

fn build_failed(
    phase: WorkflowPhase,
    run_id: &RunId,
    projection: &RunProjection,
) -> Result<RunItemV1> {
    PhaseReceiptBuilder::new(
        phase,
        RunItemStatus::Failed,
        std::slice::from_ref(run_id),
        std::slice::from_ref(projection),
    )
    .build()
}

fn failed_projection(run_id: &RunId, summary: &str) -> RunProjection {
    let mut projection = projection(run_id.clone(), RunItemStatus::Failed);
    projection.terminal.as_mut().unwrap().summary = SafeText::operator_visible(summary);
    projection
}

fn receipt_continuation(item: &RunItemV1) -> &WorkflowContinuation {
    let RunItemV1::PhaseReceipt { continuation, .. } = item else {
        panic!("expected a phase receipt: {item:?}");
    };
    continuation
}

#[test]
fn failed_map_receipt_asks_the_operator_to_rebuild_the_context() {
    let run_id = run_id();
    let projection = failed_projection(
        &run_id,
        "context:build failed | Context inventory exceeded the 100000-entry coverage limit",
    );

    let item = build_failed(WorkflowPhase::Map, &run_id, &projection).unwrap();

    let WorkflowContinuation::Retry { reason } = receipt_continuation(&item) else {
        panic!("failed map must ask for a rebuild via Retry: {item:?}");
    };
    assert_eq!(
        reason.as_str(),
        "rebuild the map context — a coverage cap was hit: scope the target (or audit via shards) first",
    );
}

#[test]
fn failed_map_receipt_asks_for_rebuild_even_when_the_failure_class_is_unknown() {
    let run_id = run_id();
    let projection = failed_projection(&run_id, "scanner worker exited abnormally");

    let item = build_failed(WorkflowPhase::Map, &run_id, &projection).unwrap();

    let WorkflowContinuation::Retry { reason } = receipt_continuation(&item) else {
        panic!("failed map must ask for a rebuild via Retry: {item:?}");
    };
    assert_eq!(
        reason.as_str(),
        "rebuild the current-revision map context after inspecting the failure evidence",
    );
}

#[test]
fn failed_map_receipt_offers_one_retry_and_keeps_the_inspect_escape_hatch() {
    let run_id = run_id();
    let projection = failed_projection(&run_id, "scanner worker exited abnormally");

    let item = build_failed(WorkflowPhase::Map, &run_id, &projection).unwrap();

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    let retries = offered_actions
        .iter()
        .filter(|action| matches!(action, WorkflowContinuation::Retry { .. }))
        .count();
    assert_eq!(retries, 1, "rebuild ask must not duplicate the generic retry");
    assert!(offered_actions
        .iter()
        .any(|action| matches!(action, WorkflowContinuation::InspectRun { .. })));
}

#[test]
fn failed_scan_receipt_drafts_remediation_into_the_inspect_reason() {
    let run_id = run_id();
    let projection = failed_projection(
        &run_id,
        "sast:scan failed | run-item stream budget exhausted",
    );

    let item = build_failed(WorkflowPhase::Scan, &run_id, &projection).unwrap();

    let WorkflowContinuation::InspectRun { reason, .. } = receipt_continuation(&item) else {
        panic!("failed scan continues with InspectRun: {item:?}");
    };
    assert_eq!(
        reason.as_str(),
        "the run hit its budget cap — raise the budget or narrow scope, then retry",
    );
}

#[test]
fn failed_scan_receipt_keeps_generic_inspect_reason_for_unknown_failures() {
    let run_id = run_id();
    let projection = failed_projection(&run_id, "scanner worker exited abnormally");

    let item = build_failed(WorkflowPhase::Scan, &run_id, &projection).unwrap();

    let WorkflowContinuation::InspectRun { reason, .. } = receipt_continuation(&item) else {
        panic!("failed scan continues with InspectRun: {item:?}");
    };
    assert_eq!(
        reason.as_str(),
        "inspect the incomplete phase evidence before retrying",
    );
}

#[test]
fn derives_interactions_and_clean_scan_destination_from_typed_projection() {
    let run_id = run_id();
    let question_id = RunQuestionId::new();
    let mut projection = projection(run_id.clone(), RunItemStatus::Completed);
    projection.finding_deltas.push(FindingDeltaSummary {
        added: 0,
        updated: 0,
        removed: 0,
        store_watermark: SafeText::operator_visible("ledger:7"),
        finding_id_samples: Vec::new(),
    });
    projection
        .questions
        .insert(question_id, question(question_id, true));

    let item = build(&run_id, &projection).unwrap();

    assert!(matches!(
        item,
        RunItemV1::PhaseReceipt {
            interaction_count: 1,
            continuation: WorkflowContinuation::OpenReport { .. },
            ..
        }
    ));
}

#[test]
fn receipt_keeps_only_the_last_finding_delta_per_run() {
    let run_id = run_id();
    let mut projection = projection(run_id.clone(), RunItemStatus::Completed);
    for (added, updated) in [(9_u64, 1_u64), (13, 2)] {
        projection.finding_deltas.push(FindingDeltaSummary {
            added,
            updated,
            removed: 0,
            store_watermark: SafeText::operator_visible("ledger:7"),
            finding_id_samples: Vec::new(),
        });
    }

    let item = build(&run_id, &projection).unwrap();

    let RunItemV1::PhaseReceipt { finding_delta, .. } = item else {
        panic!("expected phase receipt");
    };
    assert_eq!(
        (finding_delta.added, finding_delta.updated),
        (13, 2),
        "an orchestrator's end-of-run delta supersedes nested engine deltas"
    );
}

#[test]
fn completed_receipt_rejects_non_complete_referenced_run() {
    let run_id = run_id();
    let projection = projection(run_id.clone(), RunItemStatus::Partial);

    let error = build(&run_id, &projection).unwrap_err();

    assert!(error.to_string().contains("non-complete run"));
}

#[test]
fn outstanding_question_is_the_primary_continuation() {
    let run_id = run_id();
    let question_id = RunQuestionId::new();
    let mut projection = projection(run_id.clone(), RunItemStatus::Completed);
    projection
        .questions
        .insert(question_id, question(question_id, false));

    let item = build(&run_id, &projection).unwrap();

    assert!(matches!(
        item,
        RunItemV1::PhaseReceipt {
            continuation: WorkflowContinuation::AwaitDecision { question_id: actual },
            ..
        } if actual == question_id
    ));

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    assert!(!offered_actions
        .iter()
        .any(|action| matches!(action, WorkflowContinuation::NoFurtherAction { .. })));
}

#[test]
fn completed_receipt_preserves_select_without_navigation() {
    let run_id = run_id();
    let projection = projection(run_id.clone(), RunItemStatus::Completed);

    let item = build(&run_id, &projection).unwrap();

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    assert!(offered_actions
        .iter()
        .any(|action| matches!(action, WorkflowContinuation::NoFurtherAction { .. })));
}

/// A healthy, durable run that ends partial is honest partial evidence: the
/// operator must be able to accept it (select) AND explicitly continue to
/// the next phase with it — recovery actions stay alongside.
#[test]
fn selectable_partial_map_receipt_offers_select_and_next_phase_continue() {
    let run_id = run_id();
    let projection = projection(run_id.clone(), RunItemStatus::Partial);

    let item = PhaseReceiptBuilder::new(
        WorkflowPhase::Map,
        RunItemStatus::Partial,
        std::slice::from_ref(&run_id),
        std::slice::from_ref(&projection),
    )
    .build()
    .unwrap();

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    assert!(
        offered_actions
            .iter()
            .any(|action| matches!(action, WorkflowContinuation::NoFurtherAction { .. })),
        "partial evidence must be selectable: {offered_actions:?}"
    );
    assert!(
        offered_actions.iter().any(|action| matches!(
            action,
            WorkflowContinuation::OpenPhase {
                phase: WorkflowPhase::Scan
            }
        )),
        "partial map must offer an explicit continue-to-Scan hand-off: {offered_actions:?}"
    );
    assert!(offered_actions
        .iter()
        .any(|action| matches!(action, WorkflowContinuation::Retry { .. })));
}

/// A selection-blocked partial stays recovery-only: no select, no continue.
#[test]
fn blocked_partial_receipt_offers_no_select_or_continue() {
    let run_id = run_id();
    let projection = projection(run_id.clone(), RunItemStatus::Partial);

    let item = PhaseReceiptBuilder::new(
        WorkflowPhase::Map,
        RunItemStatus::Partial,
        std::slice::from_ref(&run_id),
        std::slice::from_ref(&projection),
    )
    .with_selection_blocked_reason(Some("terminal durability failed"))
    .build()
    .unwrap();

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    assert!(!offered_actions.iter().any(|action| matches!(
        action,
        WorkflowContinuation::NoFurtherAction { .. } | WorkflowContinuation::OpenPhase { .. }
    )));
}
