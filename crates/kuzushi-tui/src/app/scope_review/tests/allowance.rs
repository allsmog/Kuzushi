use super::*;
use crate::app::{InputMode, ViewHydrationKey, ViewHydrationResult, ViewHydrationValue};
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};
use kuzushi_core::runtime::RuntimeCostReport;
use kuzushi_core::workspace::ScanScopeGeneration;
use std::sync::Arc;

fn generated_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    let state = app.router.scope_review_mut().as_mut().unwrap();
    Arc::make_mut(state.review.as_mut().unwrap())
        .record
        .generation = Some(ScanScopeGeneration {
        schema_version: 1,
        model: "operator:model".into(),
        run_id: "owned-scope-generation".into(),
        prompt_sha256: "a".repeat(64),
        draft_sha256: "b".repeat(64),
        context_ref: None,
        input_bytes: 100,
        supplied_files: 2,
        inventoried_files: 2,
        limitations: vec!["Owned projection fixture, no provider request".into()],
    });
    (root, app)
}

#[test]
fn scope_allowance_binding_uses_only_the_displayed_generation_run() {
    let (_root, mut app) = generated_fixture();
    let expected = ViewHydrationKey::InvestigationAllowance {
        run_refs: vec!["owned-scope-generation".into()],
    };
    assert_eq!(app.investigation_allowance_key(), Some(expected));
    app.router.scope_review_mut().as_mut().unwrap().open = false;
    assert!(app.investigation_allowance_key().is_none());
}

fn snapshot() -> Arc<AllowanceSnapshot> {
    Arc::new(AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "owned-shared-investigation".into(),
        revision: 3,
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
    })
}

fn seed(app: &ShellApp, value: crate::app::InvestigationAllowanceRead) {
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key: app.investigation_allowance_key().unwrap(),
            value: ViewHydrationValue::InvestigationAllowance(value),
        });
}

#[test]
fn scope_allowance_is_readable_at_all_sizes_without_changing_the_draft() {
    let (_root, mut app) = generated_fixture();
    app.set_input("preserved operator draft");
    app.set_cursor(7);
    seed(&app, Ok(Some(snapshot())));
    let original = app.scope_review().unwrap().review.clone();
    for mode in [InputMode::Prompt, InputMode::Navigate] {
        app.set_input_mode(mode);
        for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
            app.reduce_resize(width, height);
            app.router
                .scope_review_mut()
                .as_mut()
                .unwrap()
                .detail_reader
                .open = width == 40;
            let frame = super::reading::screen(&app, width, height);
            let text = frame.replace('│', " ");
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            for fact in [
                "calls 5/7",
                "2 calls left",
                "1 unsettled",
                "2 Review protected",
                "cost not recorded",
            ] {
                assert!(text.contains(fact), "{width}x{height}: {text}");
            }
            assert!(!text.contains("$0"), "{text}");
        }
    }
    let plain = crate::renderer::render_plain_app(&app, 200);
    assert!(plain.contains("Shared investigation: owned-shared-investigation r3"));
    assert!(plain.contains("0 other calls left"));
    assert!(plain.contains("Dollar ceiling: not enforced"));
    assert_eq!(app.scope_review().unwrap().review, original);
    assert_eq!((app.input(), app.cursor()), ("preserved operator draft", 7));
}

#[test]
fn scope_allowance_loading_absence_and_failures_never_claim_free_work() {
    let (_root, mut app) = generated_fixture();
    let text = crate::renderer::render_plain_app(&app, 200);
    assert!(text.contains("Shared allowance: calls loading"), "{text}");
    for (value, label) in [
        (Ok(None), "calls unapproved"),
        (Err("Owned ledger failure".into()), "calls unavailable"),
    ] {
        seed(&app, value);
        for (width, height) in [(120, 36), (40, 12)] {
            app.reduce_resize(width, height);
            app.router
                .scope_review_mut()
                .as_mut()
                .unwrap()
                .detail_reader
                .open = true;
            let text = super::reading::screen(&app, width, height);
            assert!(text.contains(label), "{text}");
            assert!(!text.contains("$0"), "{text}");
        }
    }
    let text = crate::renderer::render_plain_app(&app, 200);
    assert!(text.contains("Shared allowance read failed: Owned ledger failure"));
    assert!(text.contains("cost unknown"));
}

#[test]
fn switching_scope_generation_rejects_a_late_read_for_the_previous_run() {
    let (_root, mut app) = generated_fixture();
    seed(&app, Ok(Some(snapshot())));
    let old_key = app.investigation_allowance_key().unwrap();
    let state = app.router.scope_review_mut().as_mut().unwrap();
    Arc::make_mut(state.review.as_mut().unwrap())
        .record
        .generation
        .as_mut()
        .unwrap()
        .run_id = "another-owned-generation".into();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key: old_key,
            value: ViewHydrationValue::InvestigationAllowance(Ok(Some(snapshot()))),
        });
    let text = crate::renderer::render_plain_app(&app, 200);
    assert!(text.contains("Shared allowance: calls loading"), "{text}");
    assert!(!text.contains("calls 5/7"), "{text}");
}

#[test]
fn manual_scope_overlay_does_not_borrow_the_underlying_phase_allowance() {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
    let (root, mut app) = generated_fixture();
    crate::test_support::record_indexed_run(
        root.path(),
        "owned-map",
        "sast:scan",
        json!({"ok":true}),
    );
    let attempt = crate::test_support::append_typed_attempt(
        root.path(),
        crate::app::WorkflowPhase::Map,
        "owned-map",
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(root.path(), &attempt);
    app.refresh_phase_attempt_projection();
    app.set_shell_view(ShellView::Workbench);
    let state = app.router.scope_review_mut().as_mut().unwrap();
    Arc::make_mut(state.review.as_mut().unwrap())
        .record
        .generation = None;
    state.open = false;
    assert_eq!(
        app.investigation_allowance_key(),
        Some(ViewHydrationKey::InvestigationAllowance {
            run_refs: vec!["owned-map".into()]
        })
    );
    app.router.scope_review_mut().as_mut().unwrap().open = true;
    assert!(app.investigation_allowance_key().is_none());
    assert!(crate::ui_view_models::investigation_allowance_model(&app).is_none());
}

#[test]
fn changing_target_cannot_reuse_scope_accounting_with_the_same_run_id() {
    let (_root, mut app) = generated_fixture();
    seed(&app, Ok(Some(snapshot())));
    let old = app.scope_review().unwrap().clone();
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    let mut changed = old;
    changed.target = other.path().into();
    *app.router.scope_review_mut() = Some(changed);
    let text = crate::renderer::render_plain_app(&app, 200);
    assert!(text.contains("Shared allowance: calls loading"), "{text}");
    assert!(!text.contains("calls 5/7"), "{text}");
}

#[test]
fn scope_overlay_cannot_label_its_accounting_as_the_underlying_jobs() {
    let (root, mut app) = generated_fixture();
    let mut scope = app.scope_review().unwrap().clone();
    let mut config = app.config().clone();
    config.model = Some("openai-codex:gpt-5.5".into());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    kuzushi_core::ModuleRegistry::with_v2_builtins()
        .execute_tool("campaign:study", json!({
            "campaignId":"owned-underlying-jobs", "investigationId":"another-investigation", "trials":3,
            "scanInput":{"taskMode":"manual", "tasks":["secret-scan"], "threatModelRef":null}
        }), &ctx).unwrap();
    app.open_campaign_view(Some("owned-underlying-jobs".into()));
    let current_target = app.target_owned().unwrap();
    assert_eq!(scope.target.canonicalize().unwrap(), current_target);
    scope.target = current_target;
    scope.open = false;
    *app.router.scope_review_mut() = Some(scope);
    assert!(matches!(
        app.investigation_allowance_key(),
        Some(ViewHydrationKey::StudyAllowance { .. })
    ));
    app.router.scope_review_mut().as_mut().unwrap().open = true;
    assert!(
        app.scope_review_is_visible(),
        "view {:?}; target {:?}; scope {:?}",
        app.shell_view(),
        app.target_owned(),
        app.router
            .scope_review()
            .as_ref()
            .map(|state| &state.target)
    );
    assert!(app.study_allowance_selection().is_none());
    seed(&app, Ok(Some(snapshot())));
    let model = crate::ui_view_models::investigation_allowance_model(&app).unwrap();
    assert!(!model
        .rows
        .iter()
        .any(|row| row.contains("owned-underlying-jobs")));
    let state = app.router.scope_review_mut().as_mut().unwrap();
    Arc::make_mut(state.review.as_mut().unwrap())
        .record
        .generation = None;
    assert!(app.investigation_allowance_key().is_none());
}
