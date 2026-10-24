use super::*;

fn empty_study(root: &std::path::Path, id: &str) {
    kuzushi_core::capabilities::campaign::compile_scan_batch_plan(
        kuzushi_core::capabilities::campaign::ScanBatchPlanSpec {
            root,
            batch_id: Some(id.into()),
            trials: 3,
            requested_workers: 1,
            gate_policy: Default::default(),
            prepared_input: serde_json::json!({"taskMode":"manual","tasks":["secret-scan"]}),
            config: &V2Config::default(),
            registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
        },
    )
    .unwrap();
}

#[test]
fn pending_study_with_no_observations_has_zero_paged_matches_in_a_large_ledger() {
    let (root, mut app, writer) = fixture();
    let outside = (0..500)
        .map(|index| {
            Finding::new_tool(
                "owned-fixture",
                &format!("outside.{index}"),
                "owned.rs",
                1,
                None,
                kuzushi_core::Severity::Critical,
                "Labeled outside-study observation",
            )
        })
        .collect::<Vec<_>>();
    writer.insert_findings("initial", &outside).unwrap();
    kuzushi_core::capabilities::campaign::compile_scan_batch_plan(
        kuzushi_core::capabilities::campaign::ScanBatchPlanSpec {
            root: root.path(),
            batch_id: Some("owned-empty-study".into()),
            trials: 3,
            requested_workers: 1,
            gate_policy: Default::default(),
            prepared_input: serde_json::json!({"taskMode":"manual","tasks":["secret-scan"]}),
            config: &V2Config::default(),
            registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
        },
    )
    .unwrap();
    app.open_batch_results("owned-empty-study");
    let request = app.findings_read_request(1, root.path().join("operator"), None);
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    assert_eq!(
        snapshot.page.total, 0,
        "A study is not a post-page display filter"
    );
    assert!(snapshot.report.findings.is_empty());
    assert_eq!(
        snapshot.corpus.len(),
        501,
        "A view filter cannot forge Review completion"
    );
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/owned-empty-study/queue.json")
        .exists());
}

#[test]
fn clearing_a_study_restores_workspace_paging_and_retains_the_composer_draft() {
    let (root, mut app, _writer) = fixture();
    app.router.campaign_mut().active_batch_id = Some("missing-study".into());
    app.set_input("Held operator draft\nsecond line");
    app.clear_batch_scope();
    let request = app.findings_read_request(1, root.path().join("operator"), None);
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    assert_eq!(snapshot.page.total, 1);
    assert_eq!(app.input(), "Held operator draft\nsecond line");
    assert!(app.domain().findings_batch_id().is_none());
}

#[test]
fn conflicting_selected_and_explicit_study_filters_refuse_without_overriding_either() {
    let mut filter = FindingListFilter::from_filter_expression("batch:explicit-study").unwrap();
    let before = filter.clone();
    let error = bind_review_batch(&mut filter, Some("selected-study")).unwrap_err();
    assert!(error
        .to_string()
        .contains("differs from the selected Review study"));
    assert_eq!(filter, before);
}

#[test]
fn unreadable_study_refresh_never_clears_membership_or_widens_to_workspace_history() {
    let (root, mut app, _writer) = fixture();
    app.router.campaign_mut().active_batch_id = Some("missing-study".into());
    app.refresh_campaign_deck();
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("missing-study")
    );
    assert!(app.router.campaign().active_batch_report().is_none());
    assert!(app
        .router
        .campaign()
        .notice
        .as_deref()
        .unwrap()
        .contains("report unavailable"));
    let request = app.findings_read_request(1, root.path().join("operator"), None);
    assert!(read_findings_projection(root.path(), &request).is_err());
    assert!(crate::ui_view_models::visible_sorted_finding_alias_indices(&app).is_empty());
}

#[test]
fn refresh_recovers_the_selected_study_summary_without_reopening_or_clearing_filters() {
    let (root, mut app, _writer) = fixture();
    let id = "owned-empty-study";
    empty_study(root.path(), id);
    app.open_batch_results(id);
    app.set_active_findings_filter(Some("limit:2".into()));
    app.set_input("Held recovery draft");
    let plan = kuzushi_core::capabilities::campaign::campaign_plan_path(root.path(), id);
    let backup = root.path().join("plan.saved");
    std::fs::rename(&plan, &backup).unwrap();
    app.handle_command(ShellCommand::FindingsRefresh);
    assert!(app.router.campaign().active_batch_report().is_none());
    assert_eq!(
        app.findings_read_feedback().unwrap().population_title(),
        "FINDINGS · study unavailable"
    );
    std::fs::rename(backup, plan).unwrap();
    app.handle_command(ShellCommand::FindingsRefresh);
    assert!(app.findings_read_feedback().is_none());
    assert_eq!(
        app.router
            .campaign()
            .active_batch_report()
            .unwrap()
            .batch_id,
        id
    );
    assert_eq!(app.active_findings_filter().as_deref(), Some("limit:2"));
    assert_eq!(app.input(), "Held recovery draft");
    assert_eq!(app.findings_total_count(), 0);
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/owned-empty-study/queue.json")
        .exists());
}

#[test]
fn invalid_severity_receipt_warns_without_widening_membership_or_clearing_a_draft() {
    let (root, mut app, _writer) = fixture();
    let id = "owned-empty-study";
    empty_study(root.path(), id);
    let gate = root
        .path()
        .join(".kuzushi/v3/campaigns")
        .join(id)
        .join("gate.json");
    std::fs::write(gate, b"not json").unwrap();
    app.open_batch_results(id);
    app.set_input("Held assessment recovery draft");
    let request = app.findings_read_request(1, root.path().join("operator"), None);
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    assert!(snapshot
        .page_recovery_notice
        .as_deref()
        .unwrap()
        .contains("assessment unavailable"));
    assert_eq!(snapshot.page.total, 0);
    assert!(snapshot.study.as_ref().unwrap().gate.is_none());
    app.apply_findings_read_snapshot(snapshot, &request, false);
    assert!(app.router.campaign().active_batch_report().is_some());
    assert_eq!(app.router.campaign().active_batch_id.as_deref(), Some(id));
    assert_eq!(app.input(), "Held assessment recovery draft");
    assert_eq!(app.findings_total_count(), 0);
}
