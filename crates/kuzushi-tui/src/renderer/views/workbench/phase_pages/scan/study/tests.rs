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
