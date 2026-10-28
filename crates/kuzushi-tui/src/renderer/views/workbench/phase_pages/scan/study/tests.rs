use super::*;
use crate::ui_view_models::{ScanEngineOutcomeModel, ScanStudyModel, ScanStudyQueue};

fn model() -> ScanPhaseModel {
    let jobs = ["complete", "running", "queued"]
        .iter()
        .enumerate()
        .map(|(index, state)| ScanEngineOutcomeModel {
            engine: format!("Frozen component · pass {}", index + 1),
            tool_key: None,
            outcome: (*state).into(),
            run_ref: None,
            detail: None,
        })
        .collect();
    ScanPhaseModel {
        study: Some(ScanStudyModel {
            campaign_id: "owned-study".into(),
            jobs_key: 'c',
            target: "./owned-target".into(),
            queue: Some(ScanStudyQueue {
                completed: 1,
                running: 1,
                queued: 1,
                failed: 0,
                deferred: 0,
                unknown: 0,
                jobs,
            }),
            issue: None,
        }),
        scope: "OLD_SCOPE".into(),
        plan: "OLD_PLAN".into(),
        attempt: None,
        engine_outcomes: vec![],
        empty_hint: Some("OLD_HINT".into()),
        live: None,
    }
}

fn text(lines: Vec<Line<'static>>) -> String {
    lines
        .into_iter()
        .map(|line| {
            line.spans
                .into_iter()
                .map(|span| span.content.into_owned())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn counters_keep_the_number_with_its_label_when_the_middle_column_is_narrow() {
    let model = model();
    let queue = model.study.as_ref().unwrap().queue.as_ref().unwrap();
    for width in [12, 20, 32, 38, 80] {
        let lines = queue_lines(queue, width);
        for expected in ["1/3 complete", "1 running", "1 queued"] {
            assert!(
                lines.iter().any(|line| line.contains(expected)),
                "{width}: {lines:?}"
            );
        }
        assert!(lines.iter().all(|line| display_width(line) <= width));
    }
}

#[test]
fn study_rows_keep_scope_pass_and_state_ahead_of_long_run_identifiers() {
    let mut model = model();
    for (index, job) in model
        .study
        .as_mut()
        .unwrap()
        .queue
        .as_mut()
        .unwrap()
        .jobs
        .iter_mut()
        .enumerate()
    {
        job.engine = format!("Account profile service · pass {}/3", index + 1);
        job.run_ref = Some(format!(
            "owned-study-with-a-long-run-identifier-pass-{}",
            index + 1
        ));
    }
    let before = model.clone();
    for width in [12, 20, 28, 38, 80] {
        let lines = job_lines(&model, width);
        assert!(
            lines.iter().all(|line| line.width() <= width),
            "{width}: {lines:?}"
        );
        let output = text(lines);
        let words = output.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("Account profile service"),
            "{width}: {output}"
        );
        for pass in 1..=3 {
            assert!(
                words.contains(&format!("pass {pass}/3")),
                "{width}: {output}"
            );
        }
        for state in ["complete", "running", "queued"] {
            assert!(words.contains(state), "{width}: {output}");
        }
    }
    assert_eq!(model, before);
}

#[test]
fn plain_study_rows_preserve_complete_run_references_and_failure_reasons() {
    let mut model = model();
    let job = &mut model.study.as_mut().unwrap().queue.as_mut().unwrap().jobs[0];
    let reference = "owned-completed-study-account-profile-trial-001-attempt-1";
    job.run_ref = Some(reference.into());
    job.detail = Some("Retained source could not be read; inspect the recorded attempt.".into());
    let output = text(plain_lines(&model, 40));
    let compact = output.split_whitespace().collect::<String>();
    assert!(compact.contains(reference), "{output}");
    assert!(
        compact.contains("Retainedsourcecouldnotberead;inspecttherecordedattempt."),
        "{output}"
    );
}

#[test]
fn study_sidebar_keeps_result_truth_and_points_to_exact_job_receipts() {
    let mut model = model();
    model.attempt = Some(crate::ui_view_models::ScanAttemptModel {
        attempt_id: Some("owned-attempt".into()),
        run_id: "owned-run-1".into(),
        run_refs: vec!["owned-run-1".into(), "owned-run-2".into()],
        outcome: "partial".into(),
        disposition: "awaiting disposition".into(),
        freshness: "revision not recorded".into(),
        findings: Some(1),
        findings_observed: None,
        findings_added: None,
        findings_updated: None,
        severity_counts: vec![],
        artifact_count: 0,
        artifact_paths: vec![],
        duration_secs: Some(4),
        cost_usd: None,
        cost_complete: None,
        error: Some("One scope could not be read".into()),
    });
    let before = model.clone();
    let output = text(result_lines(&model, 60));
    for expected in [
        "partial",
        "revision not recorded",
        "awaiting disposition",
        "2 run references · c study jobs",
        "4s",
        "cost not recorded",
        "One scope could not be read",
    ] {
        assert!(output.contains(expected), "{output}");
    }
    assert!(!output.contains("owned-run-1"));
    assert!(!output.contains("owned-run-2"));
    let plain = text(plain_lines(&model, 60));
    assert!(plain.contains("owned-run-1") && plain.contains("owned-run-2"));
    assert_eq!(model, before);
}

#[test]
fn study_reading_hints_use_the_resume_safe_key_at_every_surface() {
    let mut model = model();
    model.study.as_mut().unwrap().jobs_key = 'C';
    for lines in [
        scope_lines(&model, 80),
        summary_lines(&model, 80),
        receipt_lines(&model, 80),
    ] {
        let output = text(lines);
        assert!(output.contains("C study jobs"), "{output}");
        assert!(!output.contains("c study jobs"), "{output}");
    }
}

#[test]
fn plain_progress_is_exhaustive_and_does_not_borrow_an_old_result_scope_or_plan() {
    let output = text(super::super::plain_lines(&model(), 40));
    for expected in [
        "APPROVED STUDY",
        "1/3 complete",
        "1 running",
        "1 queued",
        "STUDY JOBS",
        "Frozen component · pass 1",
        "Frozen component · pass 2",
        "Frozen component · pass 3",
        "./owned-target",
        "owned-study",
    ] {
        assert!(output.contains(expected), "Missing {expected}: {output}");
    }
    for forbidden in [
        "OLD_SCOPE",
        "OLD_PLAN",
        "OLD_HINT",
        "legacy inferred",
        "delta unavailable",
    ] {
        assert!(!output.contains(forbidden), "{forbidden}: {output}");
    }
}

#[test]
fn failed_and_pending_progress_reads_remain_explicit_in_plain_output() {
    let mut model = model();
    model.study.as_mut().unwrap().queue = None;
    assert!(text(super::super::plain_lines(&model, 40)).contains("Reading study queue"));
    model.study.as_mut().unwrap().issue = Some("Owned unreadable queue".into());
    let output = text(super::super::plain_lines(&model, 40));
    assert!(
        output.contains("Study queue unavailable") && output.contains("Owned unreadable queue")
    );
    assert!(!output.contains("1/3 complete") && !output.contains("OLD_PLAN"));
}
