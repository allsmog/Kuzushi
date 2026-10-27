use super::*;
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};
use kuzushi_core::runtime::RuntimeCostReport;
use kuzushi_core::{ModuleRegistry, ToolExecutionContext};

fn jobs_fixture() -> (tempfile::TempDir, ShellApp, String) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned source, never executed\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = ModuleRegistry::with_v2_builtins()
        .execute_tool(
            "campaign:study",
            serde_json::json!({
                "campaignId":"owned-jobs","investigationId":"shared-accounting","trials":3,
                "scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}
            }),
            &ctx,
        )
        .unwrap();
    let digest = output["data"]["planSha256"].as_str().unwrap().to_owned();
    let mut app = ShellApp::new(config, Some(&workspace));
    app.open_campaign_view(Some("owned-jobs".into()));
    (root, app, digest)
}

#[test]
fn selected_fixed_jobs_keep_the_exact_shared_allowance_visible() {
    let (_root, mut app, digest) = jobs_fixture();
    let expected = ViewHydrationKey::StudyAllowance {
        campaign_id: "owned-jobs".into(),
        plan_sha256: digest,
    };
    assert_eq!(app.investigation_allowance_key(), Some(expected));
    app.set_input("retained draft");
    app.set_cursor(4);
    let context = crate::ui_view_models::context_strip_model(&app);
    assert!(
        context.cost.is_none(),
        "The selected investigation owns its accounting"
    );
    seed(&app, Ok(Some(Arc::new(snapshot()))));
    for mode in [InputMode::Prompt, InputMode::Navigate] {
        app.set_input_mode(mode);
        for detail in [false, true] {
            app.router.campaign_mut().job_detail = detail;
            for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
                app.reduce_resize(width, height);
                for scroll in [0, usize::MAX] {
                    app.router.campaign_mut().read_scroll = scroll;
                    let frame = screen(&app);
                    assert!(
                        frame.contains("calls 5/7"),
                        "{mode:?} {detail} {width}x{height}: {frame}"
                    );
                    assert!(
                        frame.contains("2 Review protected"),
                        "{mode:?} {detail} {width}x{height}: {frame}"
                    );
                    assert!(!frame.contains("session:$0"), "{frame}");
                }
            }
        }
    }
    assert_eq!((app.input(), app.cursor()), ("retained draft", 4));
}

fn snapshot() -> AllowanceSnapshot {
    AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "shared-accounting".into(),
        revision: 1,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 7,
            protected_review_calls: 2,
        },
        committed_calls: 5,
        review_calls: 0,
        unresolved_calls: 1,
        cost: RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    }
}

fn seed(app: &ShellApp, value: InvestigationAllowanceRead) {
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key: app.investigation_allowance_key().unwrap(),
            value: ViewHydrationValue::InvestigationAllowance(value),
        });
}

fn screen(app: &ShellApp) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn losing_the_selected_plan_digest_never_uses_cached_or_phase_accounting() {
    let (_root, mut app, _) = jobs_fixture();
    seed(&app, Ok(Some(Arc::new(snapshot()))));
    app.router.campaign_mut().plan_digests.clear();
    assert!(app.investigation_allowance_key().is_none());
    let model = crate::ui_view_models::investigation_allowance_model(&app).unwrap();
    assert_eq!(model.calls, "calls unavailable");
    assert!(model
        .rows
        .iter()
        .any(|row| row.contains("Selected plan identity")));
    assert!(crate::ui_view_models::context_strip_model(&app)
        .cost
        .is_none());
    app.router.campaign_mut().detail = false;
    assert!(app.study_allowance_selection().is_none());
    app.set_target(Some(tempfile::tempdir().unwrap().path().into()));
    assert!(app.router.campaign().plan_digests.is_empty());
}

#[test]
fn missing_and_failed_jobs_accounting_stays_explicit_without_claiming_free_work() {
    let (_root, mut app, _) = jobs_fixture();
    app.reduce_resize(40, 12);
    app.set_input_mode(InputMode::Navigate);
    for (value, label) in [
        (Ok(None), "calls unapproved"),
        (Err("Owned ledger failure".into()), "calls unavailable"),
    ] {
        seed(&app, value);
        assert!(screen(&app).contains(label));
        assert!(!screen(&app).contains("session:$0"));
        assert!(crate::ui_view_models::investigation_allowance_model(&app)
            .unwrap()
            .summary
            .contains("unknown"));
    }
    app.router.campaign_mut().campaigns[0].kind = None;
    assert!(app.study_allowance_selection().is_none());
}

#[test]
fn pending_history_selection_never_borrows_the_previous_study_allowance() {
    let (_root, mut app, _) = jobs_fixture();
    seed(&app, Ok(Some(Arc::new(snapshot()))));
    app.router.campaign_mut().detail = false;
    let (_, wake) = crate::app::runtime::TerminalLoopInbox::channel_for_test();
    app.set_loop_wake(Some(wake));
    app.open_campaign_view(Some("another-study".into()));
    assert_eq!(app.pending_campaign_selection(), Some("another-study"));
    assert!(app.investigation_allowance_key().is_none());
    let model = crate::ui_view_models::investigation_allowance_model(&app).unwrap();
    assert_eq!(model.calls, "calls loading");
    assert!(model.rows[0].contains("another-study"));
    assert!(!model
        .rows
        .iter()
        .any(|row| row.contains("shared-accounting")));
    assert!(crate::ui_view_models::context_strip_model(&app)
        .cost
        .is_none());
}
