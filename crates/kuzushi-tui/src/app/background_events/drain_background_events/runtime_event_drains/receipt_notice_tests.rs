use super::*;

fn result_summary(
    tool: &str,
    status: &str,
    summary: &str,
) -> kuzushi_core::run_artifacts::RunResultSummary {
    kuzushi_core::run_artifacts::RunResultSummary {
        run_id: "owned-summary-fixture".into(),
        tool: tool.into(),
        status: status.into(),
        summary: summary.into(),
        output_lines: Vec::new(),
        output_line_count: 0,
        warnings: Vec::new(),
        warning_count: 0,
        errors: Vec::new(),
        error_count: 0,
        artifacts: Vec::new(),
        artifact_count: 0,
    }
}

#[test]
fn a_single_auxiliary_receipt_leads_with_the_actual_tool_result() {
    let mut app = app_with_terminal_run("completed");
    assert!(app.finalize_run_focus_if_idle());
    let mut receipt = app.activity().unwrap().run_focus_receipt.clone().unwrap();
    receipt.result_summaries.push(result_summary(
        "entry-points:extract",
        "completed",
        "3 source surfaces saved.",
    ));
    let text = run_receipt_notice(&receipt, Some("answer recorded"));
    assert!(
        text.starts_with("Extract entry points: 3 source surfaces saved."),
        "{text}"
    );
    assert!(text.contains("run receipt · completed"));
    assert!(text.ends_with("answer recorded"));
    assert!(!text.contains("Map ready"));
}

#[test]
fn long_output_is_recorded_once_and_the_receipt_keeps_its_reader_route() {
    let mut app = app_with_terminal_run("completed");
    app.set_input("retained operator draft");
    assert!(app.finalize_run_focus_if_idle());
    let mut receipt = app.activity().unwrap().run_focus_receipt.clone().unwrap();
    let output = "Owned source evidence and a full captured revision. ".repeat(12);
    let result = result_summary("coverage:sweep", "completed", &output);
    receipt.result_summaries.push(result.clone());
    app.log("result", &output);
    let view = app.shell_view();
    app.publish_run_focus_receipt(Some(receipt), None);
    let notice = app.advisory().notice.as_ref().unwrap();
    assert!(notice.message.contains("Sweep coverage baselines"));
    assert!(notice.message.contains("run receipt · completed"));
    assert!(notice.message.contains("full result: logs"));
    assert!(!notice.message.contains("Owned source evidence"));
    assert_eq!(
        app.log_lines()
            .iter()
            .filter(|line| line.body.contains(&output))
            .count(),
        1
    );
    assert_eq!(
        app.activity()
            .unwrap()
            .run_focus_receipt
            .as_ref()
            .unwrap()
            .result_summaries,
        vec![result]
    );
    assert_eq!(app.input(), "retained operator draft");
    assert_eq!(app.shell_view(), view);
}

#[test]
fn multiline_results_keep_their_qualifications_in_the_full_reader() {
    let mut app = app_with_terminal_run("partial");
    assert!(app.finalize_run_focus_if_idle());
    let mut receipt = app.activity().unwrap().run_focus_receipt.clone().unwrap();
    let mut result = result_summary(
        "coverage:sweep",
        "partial",
        "Tracked source unchanged. Missing scopes remain unverified.",
    );
    result.output_line_count = 2;
    receipt.result_summaries.push(result);
    let notice = run_receipt_notice(&receipt, None);
    assert!(notice.contains("run receipt · partial"));
    assert!(notice.contains("full result: logs"));
    assert!(!notice.contains("Tracked source unchanged"));
}

#[test]
fn concise_unicode_results_survive_and_long_or_empty_summaries_use_the_reader() {
    let mut app = app_with_terminal_run("completed");
    assert!(app.finalize_run_focus_if_idle());
    let mut receipt = app.activity().unwrap().run_focus_receipt.clone().unwrap();
    for (summary, compact) in [
        ("日本語の結果", true),
        ("", false),
        ("first\nqualified", false),
    ] {
        receipt.result_summaries = vec![result_summary("coverage:sweep", "completed", summary)];
        let notice = run_receipt_notice(&receipt, None);
        assert_eq!(notice.contains("full result: logs"), !compact);
        if compact {
            assert!(notice.contains(summary));
        }
    }
}

#[test]
fn compound_or_mismatched_results_keep_the_overall_outcome_primary() {
    let mut app = app_with_terminal_run("failed");
    assert!(app.finalize_run_focus_if_idle());
    let mut receipt = app.activity().unwrap().run_focus_receipt.clone().unwrap();
    receipt.result_summaries.push(result_summary(
        "entry-points:extract",
        "completed",
        "3 source surfaces saved.",
    ));
    assert!(run_receipt_notice(&receipt, None).starts_with("run receipt · failed"));
    receipt.result_summaries.push(result_summary(
        "threat-model:build",
        "failed",
        "Context could not be built.",
    ));
    assert!(run_receipt_notice(&receipt, None).starts_with("run receipt · failed"));
}

fn app_with_terminal_run(outcome: &str) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut session = ActivitySession::new("receipt-notice-run");
    session.mark_run_focus_terminal_pending(outcome);
    app.set_activity(Some(session));
    app
}

#[test]
fn failed_receipt_preserves_the_current_actionable_error() {
    let mut app = app_with_terminal_run("failed");
    app.set_error_notice("tool", "Restore the missing code-analysis component.");
    let before = app.advisory().notice.clone().unwrap();
    assert!(app.finalize_run_focus_if_idle());
    let notice = app.advisory().notice.as_ref().unwrap();
    assert_eq!(notice.severity, NoticeSeverity::Error);
    assert_eq!(notice.source, before.source);
    assert_eq!(notice.message, before.message);
    assert_eq!(notice.since, before.since);
    assert_eq!(
        app.activity()
            .unwrap()
            .run_focus_receipt
            .as_ref()
            .unwrap()
            .outcome,
        "failed"
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "run" && line.body.contains("run receipt · failed") }));
}

#[test]
fn partial_receipt_preserves_the_current_warning() {
    let mut app = app_with_terminal_run("partial");
    app.set_warn_notice("tool", "Partial result: inspect the unavailable engine.");
    assert!(app.finalize_run_focus_if_idle());
    let notice = app.advisory().notice.as_ref().unwrap();
    assert_eq!(notice.severity, NoticeSeverity::Warn);
    assert!(notice.message.contains("unavailable engine"));
}

#[test]
fn completed_receipt_does_not_hide_a_persistence_failure() {
    let mut app = app_with_terminal_run("completed");
    app.set_error_notice("session", "Result persistence failed; recovery required.");
    assert!(app.finalize_run_focus_if_idle());
    let notice = app.advisory().notice.as_ref().unwrap();
    assert_eq!(notice.severity, NoticeSeverity::Error);
    assert!(notice.message.contains("recovery required"));
}

#[test]
fn old_alert_does_not_hide_a_new_successful_run() {
    let mut app = app_with_terminal_run("completed");
    app.set_error_notice("tool", "Previous run failed.");
    app.advisory_mut().notice.as_mut().unwrap().since =
        app.activity().unwrap().started_at - Duration::from_secs(1);
    assert!(app.finalize_run_focus_if_idle());
    let notice = app.advisory().notice.as_ref().unwrap();
    assert_eq!(notice.severity, NoticeSeverity::Info);
    assert!(notice.message.contains("run receipt · completed"));
}

#[test]
fn an_incidental_warning_does_not_downgrade_a_failed_run() {
    let mut app = app_with_terminal_run("failed");
    app.set_warn_notice("paste", "Multiline paste staged.");
    assert!(app.finalize_run_focus_if_idle());
    let notice = app.advisory().notice.as_ref().unwrap();
    assert_eq!(notice.severity, NoticeSeverity::Error);
    assert!(notice.message.contains("run receipt · failed"));
    assert!(notice.message.contains("/activity"));
}

#[test]
fn receipt_without_an_alert_discloses_outcome_and_recovery() {
    for (outcome, severity, actionable) in [
        ("failed", NoticeSeverity::Error, true),
        ("partial", NoticeSeverity::Warn, true),
        ("blocked", NoticeSeverity::Warn, true),
        ("canceled", NoticeSeverity::Info, false),
        ("completed", NoticeSeverity::Info, false),
    ] {
        let mut app = app_with_terminal_run(outcome);
        assert!(app.finalize_run_focus_if_idle());
        let notice = app.advisory().notice.as_ref().unwrap();
        assert_eq!(notice.severity, severity, "{outcome}");
        assert_eq!(notice.message.contains("activity"), actionable, "{outcome}");
    }
}
