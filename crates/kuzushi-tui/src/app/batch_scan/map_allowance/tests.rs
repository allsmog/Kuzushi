use super::*;
use crate::app::{InputMode, ShellApp, ShellView};
use crate::test_support::{append_typed_attempt, record_indexed_run, select_typed_attempt};
use kuzushi_core::allowance::{
    AllowanceApprovalV1, AllowanceCall, AllowanceLimits, InvestigationWork,
};
use kuzushi_core::{modules::ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::json;

const MODEL: &str = "openai-codex:gpt-5.5";

fn accepted_map(root: &std::path::Path) -> V2Config {
    std::fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let limiter = kuzushi_core::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    limiter
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "map-investigation".into(),
            expected_revision: 0,
            model: MODEL.into(),
            limits: AllowanceLimits {
                max_provider_calls: 5,
                protected_review_calls: 2,
            },
            reason: "Offline accounting recovery test".into(),
            work_plan: None,
        })
        .unwrap();
    let reservation = limiter
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "map-investigation".into(),
            expected_revision: 1,
            request_id: "fixture-charge".into(),
            run_id: "accepted-map".into(),
            work_id: "map".into(),
            model: MODEL.into(),
            work: InvestigationWork::Context,
        })
        .unwrap();
    limiter
        .settle_provider_call(
            reservation,
            kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        )
        .unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = kuzushi_core::modules::ModuleRegistry::with_v2_builtins().execute_tool(
        "threat-model:import", json!({"document":{"version":"1","methodology":"stride",
            "dfd":{"nodes":[{"id":"app"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}},
            "allowanceRef":{"schemaVersion":1,"investigationId":"map-investigation","revision":1,"workId":"map"}}), &ctx).unwrap();
    record_indexed_run(root, "accepted-map", "threat-model:import", output);
    let attempt = append_typed_attempt(
        root,
        kuzushi_core::WorkflowPhase::Map,
        "accepted-map",
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    select_typed_attempt(root, &attempt);
    config
}

#[test]
fn ordinary_scan_form_after_restart_retains_map_accounting_and_navigation_origin() {
    let root = tempfile::tempdir().unwrap();
    let config = accepted_map(root.path());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("preserve my\nscan draft");
    app.set_cursor(4);
    app.open_batch_scan_config(None);
    let form = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!((form.trials, form.effective_workers), (3, 1));
    assert_eq!(form.study.investigation_id, "map-investigation");
    let allowance = form.study.allowance.as_ref().unwrap();
    assert_eq!(
        (
            allowance.committed_calls,
            allowance.remaining_discovery_calls(),
            allowance.protected_review_remaining()
        ),
        (1, 2, 2)
    );
    assert!(!form.study.approved());
    assert_eq!(form.study.next_action(), "Prepare study draft");
    assert_eq!(
        super::super::study_actions::allowance_terms(&form.study, MODEL).unwrap()
            ["expectedRevision"],
        1
    );
    app.close_batch_config();
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!((app.input(), app.cursor()), ("preserve my\nscan draft", 4));
}

#[test]
fn missing_accounting_displays_an_error_and_blocks_scan_and_context_allowances() {
    let root = tempfile::tempdir().unwrap();
    let config = accepted_map(root.path());
    let db = WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path();
    std::fs::remove_file(&db).unwrap();
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    let form = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(form
        .study
        .accounting_error
        .as_ref()
        .unwrap()
        .contains("Map history is damaged"));
    assert!(form
        .notice
        .as_ref()
        .unwrap()
        .contains("\nNo work can start.\n"));
    assert!(!form.notice.as_ref().unwrap().contains("worker policy"));
    assert!(super::super::study_actions::allowance_terms(&form.study, MODEL).is_err());
    assert!(super::super::launch::study_input(&app, root.path(), form, "scan-draft").is_err());
    assert!(app.launch_batch_from_config().effects.is_empty());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Map history is damaged"));
    assert!(kuzushi_core::SpendLimiter::read_allowance_snapshot(&db, "map-investigation").is_err());
    app.open_context_generation();
    assert!(app
        .handle_context_generation_key(crossterm::event::KeyCode::Enter)
        .effects
        .is_empty());
}

#[test]
fn dirty_source_change_blocks_new_implicit_study_without_resetting_accounting() {
    let root = tempfile::tempdir().unwrap();
    accepted_map(root.path());
    std::fs::write(root.path().join("main.rs"), "fn changed() {}\n").unwrap();
    let form = BatchScanConfig::load_for_new_study(root.path(), None);
    assert!(form
        .study
        .accounting_error
        .as_ref()
        .unwrap()
        .contains("earlier source content"));
    assert!(form.study.ensure_accounting_ready().is_err());
    let map = BatchScanConfig::load_for_map_study(root.path());
    assert!(map.study.ensure_accounting_ready().is_ok());
    assert_eq!(map.study.investigation_id, "map-investigation");
    assert_eq!(map.study.allowance.as_ref().unwrap().committed_calls, 1);
    assert!(
        !map.study.approved(),
        "historical spending cannot approve replacement Map work"
    );
    let db = WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path();
    let allowance =
        kuzushi_core::SpendLimiter::read_allowance_snapshot(&db, "map-investigation").unwrap();
    assert_eq!(allowance.committed_calls, 1);
}

#[test]
fn explicitly_generating_a_replacement_map_from_stale_scan_form_retains_spending() {
    let root = tempfile::tempdir().unwrap();
    let config = accepted_map(root.path());
    std::fs::write(root.path().join("main.rs"), "fn changed() {}\n").unwrap();
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .ensure_accounting_ready()
        .is_err());
    app.open_context_generation();
    let form = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(form.study.ensure_accounting_ready().is_ok());
    assert_eq!(form.study.allowance.as_ref().unwrap().committed_calls, 1);
    let update = app.handle_context_generation_key(crossterm::event::KeyCode::Enter);
    let [crate::app::ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("replacement Map must prepare a reviewable draft without executing it");
    };
    assert_eq!(request.tool_name, "campaign:context-study");
    let input: serde_json::Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    assert_eq!(input["investigationId"], "map-investigation");
}

#[test]
fn canceling_replacement_context_cannot_implicitly_scan_with_cached_stale_map() {
    let root = tempfile::tempdir().unwrap();
    let config = accepted_map(root.path());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();
    assert!(app
        .engagement
        .selected_phase_attempt(kuzushi_core::WorkflowPhase::Map)
        .is_some());
    std::fs::write(root.path().join("main.rs"), "fn changed() {}\n").unwrap();
    app.open_batch_scan_config(None);
    assert!(app
        .engagement
        .selected_phase_attempt(kuzushi_core::WorkflowPhase::Map)
        .is_none());
    app.open_context_generation();
    app.handle_context_generation_key(crossterm::event::KeyCode::Esc);
    let form = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let error =
        super::super::launch::study_input(&app, root.path(), form, "stale-draft").unwrap_err();
    assert!(format!("{error:#}").contains("earlier source content"));
    assert!(
        !kuzushi_core::capabilities::campaign::campaign_plan_path(root.path(), "stale-draft")
            .exists()
    );
    assert_eq!(form.study.allowance.as_ref().unwrap().committed_calls, 1);
}

#[test]
fn source_drift_while_a_fresh_form_is_open_refuses_automatic_context_binding() {
    let root = tempfile::tempdir().unwrap();
    let config = accepted_map(root.path());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();
    app.open_batch_scan_config(None);
    std::fs::write(root.path().join("main.rs"), "fn changed() {}\n").unwrap();
    let update = app.launch_batch_from_config();
    assert!(update.effects.is_empty());
    assert!(app
        .engagement
        .selected_phase_attempt(kuzushi_core::WorkflowPhase::Map)
        .is_none());
    let form = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(form
        .notice
        .as_ref()
        .unwrap()
        .contains("earlier source content"));
    assert_eq!(form.study.allowance.as_ref().unwrap().committed_calls, 1);
    assert!(form.study.receipt.is_none());
}
