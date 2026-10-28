use super::*;
use kuzushi_core::workflow_attempts::TargetContentIdentity;
use kuzushi_core::WorkflowPhase;

fn receipt(run: &str, outcome: Option<PhaseStageOutcome>) -> InvestigationAttemptReceipt {
    InvestigationAttemptReceipt {
        run_id: run.into(),
        run_status: None,
        source_identity: TargetContentIdentity::Unavailable {
            reason: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                "Owned receipt fixture; source applicability is unassessed",
            ),
        },
        scan: outcome.map(|outcome| PhaseStageReceipt {
            phase: WorkflowPhase::Scan,
            outcome,
            run_refs: vec![run.into()],
            scan: None,
        }),
    }
}

#[test]
fn an_empty_history_makes_no_attempt_or_completion_claim() {
    assert!(lines(&[], false).is_empty());
    assert!(lines(&[], true).is_empty());
}

#[test]
fn scope_study_history_preserves_reassessment_and_scope_before_work_totals() {
    let mut content = vec![
        "Review: source reassessment needed".into(),
        "Scope study: 7 boundaries · 0 unplanned".into(),
        "Shared allowance: existing calls".into(),
    ];
    insert_after_scope(
        &mut content,
        &[receipt("retained", Some(PhaseStageOutcome::Failed))],
        false,
    );
    assert_eq!(content[0], "Review: source reassessment needed");
    assert_eq!(content[1], "Scope study: 7 boundaries · 0 unplanned");
    assert_eq!(content[2], "Recorded attempts: 1 · 1 failed");
    assert_eq!(content[3], "Shared allowance: existing calls");
}

#[test]
fn a_successful_retry_keeps_the_failed_receipt_visible_without_more_jobs() {
    let attempts = vec![
        receipt("pass-1", Some(PhaseStageOutcome::Completed)),
        receipt("pass-2-failed", Some(PhaseStageOutcome::Failed)),
        receipt("pass-2-retry", Some(PhaseStageOutcome::Completed)),
    ];
    let before = attempts.clone();
    assert_eq!(
        lines(&attempts, false),
        ["Recorded attempts: 3 · 2 completed, 1 failed"]
    );
    let details = lines(&attempts, true).join("\n");
    assert!(details.contains("Attempt: pass-2-failed · failed"));
    assert!(details.contains("Attempt: pass-2-retry · completed"));
    assert!(!details.contains("jobs"));
    assert_eq!(attempts, before);
}

#[test]
fn missing_receipts_partial_and_skipped_work_never_become_success() {
    let attempts = vec![
        receipt("unresolved", None),
        receipt("partial", Some(PhaseStageOutcome::Partial)),
        receipt("skipped", Some(PhaseStageOutcome::Skipped)),
    ];
    let text = lines(&attempts, true).join("\n");
    assert!(text.contains("1 outcome unavailable, 1 partial, 1 skipped"));
    assert!(text.contains("Attempt: unresolved · outcome unavailable"));
    assert!(!text.contains("completed"));
}

#[test]
fn failed_attempt_history_precedes_long_context_receipts_and_keeps_the_scope() {
    let attempts = vec![receipt("retained-failure", Some(PhaseStageOutcome::Failed))];
    let mut content = vec![
        "Review: source reassessment needed".into(),
        "Scope: context matrix".into(),
    ];
    content.extend(std::iter::repeat_n("Long context receipt".into(), 100));
    content.push("Work: nested context preparation".into());
    insert_after_scope(&mut content, &attempts, true);
    assert_eq!(content[0], "Review: source reassessment needed");
    assert_eq!(content[1], "Scope: context matrix");
    assert_eq!(content[2], "Recorded attempts: 1 · 1 failed");
    assert_eq!(content[3], "Attempt: retained-failure · failed");
    assert_eq!(
        content
            .iter()
            .filter(|line| *line == "Long context receipt")
            .count(),
        100
    );
}

#[test]
fn a_recorded_cancellation_is_not_missing_engine_data_or_a_completed_attempt() {
    let mut canceled = receipt("stopped", Some(PhaseStageOutcome::Completed));
    canceled.run_status = Some("canceled".into());
    let text = lines(&[canceled], true).join("\n");
    assert!(text.contains("1 canceled"));
    assert!(text.contains("Attempt: stopped · canceled"));
    assert!(!text.contains("completed") && !text.contains("unavailable"));
}

#[test]
fn execution_status_and_engine_outcome_keep_their_distinct_meanings() {
    for status in ["failed", "blocked", "interrupted", "running"] {
        let mut attempt = receipt("known-execution", Some(PhaseStageOutcome::Completed));
        attempt.run_status = Some(status.into());
        assert_eq!(outcome_label(&attempt), status);
    }
    let mut partial = receipt("partial-engine", Some(PhaseStageOutcome::Partial));
    partial.run_status = Some("completed".into());
    assert_eq!(outcome_label(&partial), "partial");
    let mut completed = receipt("no-engine-details", None);
    completed.run_status = Some("completed".into());
    assert_eq!(outcome_label(&completed), "completed");
}

#[test]
fn an_unknown_status_or_canceled_looking_name_never_invents_cancellation() {
    let mut attempt = receipt("canceled-in-name", None);
    assert_eq!(outcome_label(&attempt), "outcome unavailable");
    attempt.run_status = Some("unrecognized\u{1b}[31mstatus".into());
    assert_eq!(outcome_label(&attempt), "outcome unavailable");
}

#[test]
fn completed_attempt_ids_do_not_bury_spending_coverage_or_settings() {
    let attempts: Vec<_> = (0..21)
        .map(|index| {
            receipt(
                &format!("owned-{index}"),
                Some(PhaseStageOutcome::Completed),
            )
        })
        .collect();
    let mut content = vec![
        "Scope study: 7 boundaries".into(),
        "Shared allowance: 1 / 3 calls".into(),
        "Coverage: selected boundaries only".into(),
        "Planned scan settings: frozen".into(),
    ];
    insert_after_scope(&mut content, &attempts, true);
    assert_eq!(content[1], "Recorded attempts: 21 · 21 completed");
    assert_eq!(content[2], "Shared allowance: 1 / 3 calls");
    assert_eq!(content[3], "Coverage: selected boundaries only");
    assert_eq!(content[4], "Planned scan settings: frozen");
    assert_eq!(
        content
            .iter()
            .filter(|line| line.starts_with("Attempt:"))
            .count(),
        21
    );
    assert_eq!(content.last().unwrap(), "Attempt: owned-20 · completed");
}
