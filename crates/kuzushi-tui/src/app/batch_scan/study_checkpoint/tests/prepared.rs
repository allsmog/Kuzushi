use super::*;
use kuzushi_core::{ToolExecutionContext, WorkspaceTarget};
use serde_json::json;

fn prepare(first: &mut ShellApp) -> serde_json::Value {
    let config = first
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.scan_input =
        Some(json!({"taskMode":"manual","tasks":["license-scan"],"threatModelRef":null}));
    config.study.campaign_id = Some("prepared-resource-choices".into());
    config.study.max_provider_calls = Some(9);
    config.study.protected_review_calls = Some(2);
    config.study.max_job_attempts = 3;
    first.checkpoint_study_choices();
    settle(first);
    let config = first.router.campaign().batch_scan_config.as_ref().unwrap();
    let workspace = WorkspaceTarget::new(&config.target).unwrap();
    let ctx = ToolExecutionContext {
        config: first.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = json!({"campaignId":"prepared-resource-choices",
        "investigationId":config.study.investigation_id, "scanInput":config.study.scan_input});
    let prepared = first
        .registry()
        .prepare_dispatch_input("campaign:study", input, &ctx, None)
        .unwrap();
    let output = first
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    first.cache_tool_snapshot("campaign:study", &output);
    first.checkpoint_study_choices();
    settle(first);
    output
}

fn approve(first: &mut ShellApp, output: &serde_json::Value) {
    let config = first.router.campaign().batch_scan_config.as_ref().unwrap();
    let workspace = WorkspaceTarget::new(&config.target).unwrap();
    let ctx = ToolExecutionContext {
        config: first.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = json!({"investigationId":config.study.investigation_id,
        "expectedRevision":0,"model":"openai-codex:gpt-5.5","maxProviderCalls":9,
        "protectedReviewCalls":2,"maxJobAttempts":3,"reason":"Owned metadata-only test",
        "campaignId":output["data"]["campaignId"],"campaignPlanSha256":output["data"]["planSha256"],
        "campaignJobs":output["data"]["jobCount"]});
    let prepared = first
        .registry()
        .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = first
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    first.cache_tool_snapshot("campaign:approve-allowance", &result);
    first.checkpoint_study_choices();
    settle(first);
}

#[test]
fn prepared_scan_keeps_unapproved_call_and_attempt_choices_after_restart() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join("note.md"),
        "Owned inert recovery fixture.\n",
    )
    .unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    prepare(&mut first);
    let config = first.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.plan_identity().is_some());
    assert!(!config.study.approved());
    assert!(
        first.study_choices_checkpointed(),
        "Prepared work must not erase unapproved spending choices"
    );
    let investigation = config.study.investigation_id.clone();
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let config = next.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.investigation_id, investigation);
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls,
            config.study.max_job_attempts
        ),
        (Some(9), Some(2), 3)
    );
    assert!(config.study.plan_identity().is_none());
    assert!(!config.study.approved());
    assert!(!next.has_running_work());
}

#[test]
fn matching_approval_resolves_the_private_resource_choices() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    let output = prepare(&mut first);
    assert!(first.study_choices_checkpointed());
    approve(&mut first, &output);
    assert!(first
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .approved());
    assert!(!first.study_choices_checkpointed());
    let next = shell(target.path(), home.path());
    assert_eq!(
        next.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::None
    );
    assert!(!next.has_running_work());
}

#[test]
fn revised_proposal_recovers_without_replacing_the_approved_ledger_limits() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    let output = prepare(&mut first);
    approve(&mut first, &output);
    first
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .max_provider_calls = Some(7);
    first.checkpoint_study_choices();
    settle(&mut first);
    assert!(first.study_choices_checkpointed());
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let study = &next
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    assert_eq!(study.max_provider_calls, Some(7));
    assert_eq!(
        study.allowance.as_ref().unwrap().limits.max_provider_calls,
        9
    );
    assert_eq!(study.allowance.as_ref().unwrap().revision, 1);
    assert!(study.plan_identity().is_none());
    assert!(!study.approved());
}

#[test]
fn approved_plan_keeps_a_partial_numeric_editor_without_granting_new_work() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    let output = prepare(&mut first);
    approve(&mut first, &output);
    let config = first
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.begin_number_edit(BatchScanConfigRow::ProviderCalls);
    config.number_edit.as_mut().unwrap().field = FieldEditor::new("1");
    first.checkpoint_study_choices();
    settle(&mut first);
    assert!(first.study_choices_checkpointed());
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let config = next.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.number_edit.as_ref().unwrap().field.text(), "1");
    assert_eq!(config.study.max_provider_calls, Some(9));
    assert_eq!(
        config
            .study
            .allowance
            .as_ref()
            .unwrap()
            .limits
            .max_provider_calls,
        9
    );
    assert!(!config.study.approved());
}
