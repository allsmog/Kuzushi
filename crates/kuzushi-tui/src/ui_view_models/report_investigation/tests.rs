use super::*;

#[test]
fn reassessment_explains_retained_decisions_and_leaves_zero_uncluttered() {
    assert!(reassessment_lines(0).is_empty());
    assert_eq!(
        reassessment_lines(1),
        vec!["Review: 1 finding needs source reassessment. Earlier decisions remain recorded."]
    );
    assert_eq!(
        reassessment_lines(2),
        vec!["Review: 2 findings need source reassessment. Earlier decisions remain recorded."]
    );
}

#[test]
fn workspace_history_explains_unverified_source_decisions_without_creating_a_verdict() {
    use kuzushi_core::workspace::WorkspaceReviewSourceApplicability;
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(std::path::PathBuf::from("/owned-report-history")));
    app.domain_mut()
        .set_review_source_applicabilities(std::collections::BTreeMap::from([
            (
                "recorded-marker".into(),
                WorkspaceReviewSourceApplicability::LaterSourceUnverified,
            ),
            (
                "current-marker".into(),
                WorkspaceReviewSourceApplicability::LatestObservation,
            ),
        ]));
    let key = crate::app::ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: app.findings_read_watermark(),
    };
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key,
            value: crate::app::ViewHydrationValue::WorkspaceReportReview(Ok(
                kuzushi_core::workspace::WorkspaceReviewSummary {
                    finding_count: 2,
                    reassessment_required: 1,
                    ..Default::default()
                },
            )),
        });
    let lines = history_lines(&app);
    assert_eq!(
        lines[0],
        "Review: 1 finding needs source reassessment. Earlier decisions remain recorded."
    );
    assert!(app.review_decisions().is_empty());
}

#[test]
fn explicit_workspace_report_discloses_lesson_preservation_and_format_omission() {
    let root = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.router.report_mut().toggle_scope();
    let lines = report_investigation_lines(&app);
    assert!(lines
        .iter()
        .any(|line| line.contains("Lessons: linked records preserved")));
    app.router.report_mut().toggle_provenance();
    let lines = report_investigation_lines(&app);
    assert!(lines
        .iter()
        .any(|line| line.contains("another source revision")));
    app.router.report_mut().move_format(4);
    let lines = report_investigation_lines(&app);
    assert!(lines.iter().any(|line| line.contains("Lessons: omitted")));
    assert!(lines
        .iter()
        .any(|line| line.contains("JSON, JSONL, SARIF and Markdown bundle")));
}

#[test]
fn current_study_adds_no_source_currency_line() {
    assert!(source_currency_lines(true).is_empty());
}

#[test]
fn earlier_source_study_never_reads_as_current() {
    let lines = source_currency_lines(false);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("Recorded on earlier source"));
    assert!(lines[0].contains("does not describe them"));
}

#[test]
fn report_shows_the_plans_goal_instead_of_the_latest_target_goal() {
    use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
    use serde_json::json;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "// Inert report fixture\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let first = registry.execute_tool("campaign:brief", json!({
        "mode":"save","expectedRevision":0,"text":"Original policy priorities\nKeep owner questions."
    }), &context).unwrap();
    let plan = registry
        .execute_tool(
            "campaign:study",
            json!({
                "campaignId":"brief-report","investigationId":"brief-report",
                "briefRef":first["data"]["brief"]["reference"],
                "scanInput":{"taskMode":"manual","tasks":["license-scan"],"threatModelRef":null}
            }),
            &context,
        )
        .unwrap();
    let approval = registry
        .prepare_dispatch_input(
            "campaign:approve-allowance",
            json!({
                "campaignId":"brief-report","investigationId":"brief-report","expectedRevision":0,
                "campaignPlanSha256":plan["data"]["planSha256"],"campaignJobs":3,"maxJobAttempts":1,
                "model":"openai-codex:gpt-5.5","maxProviderCalls":1,"protectedReviewCalls":1,
                "reason":"Offline report fixture; no jobs started"
            }),
            &context,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(approval, &context, None)
        .unwrap();
    registry
        .execute_tool(
            "campaign:brief",
            json!({
                "mode":"save","expectedRevision":1,"text":"New unrelated priorities"
            }),
            &context,
        )
        .unwrap();
    let document =
        kuzushi_core::workspace::load_investigation_report_document(&workspace, "brief-report")
            .unwrap();
    let app = ShellApp::new(config, Some(&workspace));
    let lines = selected_document_lines(&app, &document).join("\n");
    assert!(lines.contains("Operator brief: repository · revision 1"));
    assert!(lines.contains("Original policy priorities\nKeep owner questions."));
    assert!(!lines.contains("New unrelated priorities"));
    assert!(lines.contains("finding decisions remain based on evidence"));
}
