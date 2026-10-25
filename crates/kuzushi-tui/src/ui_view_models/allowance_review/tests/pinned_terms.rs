use super::*;
use kuzushi_core::{modules::ToolExecutionContext, WorkspaceTarget};
use serde_json::json;

fn prepared_approval(calls: u64, review: u64, selector: &str) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.md"),
        "Owned inert approval fixture.\n",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = registry.execute_tool("campaign:study", json!({"campaignId":"pinned-study",
        "investigationId":"operator-study","scanInput":{"taskMode":"manual","tasks":["license-scan"],"threatModelRef":null}}), &ctx).unwrap();
    let receipt: kuzushi_core::capabilities::campaign::StudyPlanReceipt =
        serde_json::from_value(output["data"].clone()).unwrap();
    let input = json!({"investigationId":"operator-study","expectedRevision":0,"model":selector,
        "maxProviderCalls":calls,"protectedReviewCalls":review,"reason":"Owned bounded approval test",
        "campaignId":receipt.campaign_id,"campaignJobs":receipt.job_count,
        "campaignPlanSha256":receipt.plan_sha256,"maxJobAttempts":1});
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
        .unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .receipt = Some(receipt);
    let descriptor = registry.resolve_tool("campaign:approve-allowance").unwrap();
    let confirm = crate::app::descriptor_approval_confirm(descriptor, prepared.value()).unwrap();
    let mut confirm = crate::allowance::with_accounting_terms(&app, prepared.value(), confirm);
    confirm
        .rationale
        .as_mut()
        .unwrap()
        .push_str(&"\nOwned detailed boundary terms remain available.".repeat(80));
    app.request_confirm_for_run(
        confirm,
        crate::app::RunToolLaunch {
            tool_name: "campaign:approve-allowance".into(),
            input: prepared,
            workspace,
            thinking_level: None,
            authorization: Default::default(),
        },
    );
    (root, app)
}

#[test]
fn approved_limits_model_and_fixed_work_remain_visible_at_both_ends_at_every_size() {
    let (root, mut app) = prepared_approval(29, 2, "openai-codex:gpt-5.5");
    app.set_input("retained allowance draft λ");
    app.set_cursor(6);
    for &(columns, rows) in SIZES {
        app.set_viewport(TerminalViewport {
            columns,
            rows: rows - 1,
        });
        key(&mut app, KeyCode::Home);
        assert!(!model(&app).allows_approval());
        key(&mut app, KeyCode::Char('y'));
        assert!(app.advisory().pending_confirm.is_some());
        for code in [KeyCode::Home, KeyCode::End] {
            key(&mut app, code);
            let text = rendered(&app);
            let terms = if columns < 76 {
                vec!["Total calls 29", "Review reserve 2", "3 jobs", "workers 1"]
            } else {
                vec![
                    "Total provider calls: 29",
                    "Protected review calls: 2",
                    "3 fixed jobs",
                    "1 worker(s)",
                ]
            };
            for term in terms {
                assert!(text.contains(term), "{columns}x{rows}: {term}: {text}");
            }
            assert!(text.contains("Allowance: openai-oauth:gpt-5.5"));
            assert!(text.contains("$ unknown"));
            assert!(model(&app).page_rows > 0);
        }
        assert!(model(&app).allows_approval());
    }
    key(&mut app, KeyCode::Esc);
    assert_eq!(
        (app.input(), app.cursor()),
        ("retained allowance draft λ", 6)
    );
    assert!(!app.has_running_work());
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/pinned-study/queue.json")
        .exists());
}

#[test]
fn pinned_work_uses_matching_frozen_workers_and_the_parked_prepared_request() {
    let (_root, mut app) = prepared_approval(29, 2, "openai-codex:gpt-5.5");
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.requested_workers = 8;
    config.study.max_provider_calls = Some(123);
    config.study.max_job_attempts = 9;
    let text = model(&app).pinned.join("\n");
    assert!(text.contains("29") && !text.contains("123"));
    assert!(text.contains("1 worker(s)") && !text.contains("8 worker"));
    assert!(text.contains("1 attempt(s)") && !text.contains("9 attempt"));
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .receipt
        .as_mut()
        .unwrap()
        .plan_sha256 = "different-plan".into();
    assert!(model(&app).pinned.join("\n").contains("unknown worker(s)"));
    app.request_confirm(request(false));
    assert!(model(&app).pinned.is_empty());
}

#[test]
fn zero_calls_and_long_selectors_keep_readable_limits_and_exhaustive_plain_terms() {
    let selector = format!("openai-codex:{}", "owned-long-selector-".repeat(8));
    let (_root, mut app) = prepared_approval(0, 0, &selector);
    app.set_viewport(TerminalViewport {
        columns: 40,
        rows: 11,
    });
    key(&mut app, KeyCode::End);
    let text = rendered(&app);
    assert!(
        text.contains("Total calls 0")
            && text.contains("Review reserve 0")
            && text.contains("$ unknown")
    );
    assert!(model(&app).allows_approval());
    let plain = crate::renderer::render_plain_app(&app, 120);
    assert!(plain
        .split_whitespace()
        .collect::<String>()
        .contains(&crate::app::display_model_selector(&selector)));
    assert!(plain.contains("ZERO PROVIDER CALLS"));
    assert!(!app.has_running_work());
}

fn approval_with_recorded_spending() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = prepared_approval(7, 2, "openai-codex:gpt-5.5");
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .allowance = Some(kuzushi_core::allowance::AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "operator-study".into(),
        revision: 0,
        model: "openai-codex:gpt-5.5".into(),
        limits: kuzushi_core::allowance::AllowanceLimits {
            max_provider_calls: 6,
            protected_review_calls: 2,
        },
        committed_calls: 4,
        review_calls: 0,
        unresolved_calls: 1,
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    });
    (root, app)
}

#[test]
fn recorded_spending_and_proposed_capacity_stay_visible_at_the_approval_control() {
    let (_root, mut app) = approval_with_recorded_spending();
    for &(columns, rows) in SIZES {
        app.set_viewport(TerminalViewport {
            columns,
            rows: rows - 1,
        });
        for code in [KeyCode::Home, KeyCode::End] {
            key(&mut app, code);
            let text = rendered(&app);
            let required = if columns < 76 {
                ["Used 4 · left Scan 1 Review 2", "Total calls 7"]
            } else {
                [
                    "Recorded calls: 4 committed · 1 unsettled",
                    "Left under proposed limits: 1 context/scan · 2 protected Review",
                ]
            };
            for term in required {
                assert!(text.contains(term), "{columns}x{rows}: missing {term}");
            }
            assert!(text.contains("$ unknown"));
            assert!(model(&app).page_rows > 0);
        }
        assert!(model(&app).allows_approval());
        assert!(rendered(&app).contains("y approve"));
    }
    assert!(!app.has_running_work());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .allowance
            .as_ref()
            .unwrap()
            .limits
            .max_provider_calls,
        6
    );
}

#[test]
fn pinned_accounting_never_uses_an_unrelated_or_unreadable_snapshot() {
    for problem in ["investigation", "revision", "error"] {
        let (_root, mut app) = approval_with_recorded_spending();
        let study = &mut app
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study;
        match problem {
            "investigation" => study.allowance.as_mut().unwrap().investigation_id = "other".into(),
            "revision" => study.allowance.as_mut().unwrap().revision = 1,
            _ => study.accounting_error = Some("unavailable".into()),
        }
        let text = model(&app).pinned.join("\n");
        assert!(!text.contains("Recorded") && !text.contains("Left:"));
    }
}

#[test]
fn consumed_review_capacity_is_not_presented_as_still_protected() {
    let (_root, mut app) = approval_with_recorded_spending();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .allowance
        .as_mut()
        .unwrap()
        .review_calls = 1;
    let text = model(&app).pinned.join("\n");
    assert!(text.contains("2 context/scan · 1 protected Review"));
    assert!(!app.has_running_work());
}

#[test]
fn large_numbers_never_remove_the_compact_terms_or_approval_control() {
    let (_root, mut app) = prepared_approval(1_000_000, 333_333, "openai-codex:gpt-5.5");
    let (_other, recorded) = approval_with_recorded_spending();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .allowance = recorded
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .allowance
        .clone();
    app.set_viewport(TerminalViewport {
        columns: 40,
        rows: 11,
    });
    key(&mut app, KeyCode::End);
    assert!(model(&app).page_rows > 0 && model(&app).allows_approval());
    let text = rendered(&app);
    for term in ["1000000", "333333", "y approve", "$ unknown"] {
        assert!(text.contains(term), "missing {term}");
    }
    assert!(!app.has_running_work());
}
