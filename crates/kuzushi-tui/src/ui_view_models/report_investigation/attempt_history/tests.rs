use super::*;
use kuzushi_core::workflow_attempts::TargetContentIdentity;
use kuzushi_core::WorkflowPhase;

fn receipt(run: &str, outcome: Option<PhaseStageOutcome>) -> InvestigationAttemptReceipt {
    InvestigationAttemptReceipt {
        run_id: run.into(),
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
