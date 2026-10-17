use super::*;
use crate::findings::{read_finding_page, FindingListFilter, FindingPageRequest};

fn row(name: &str, severity: Severity) -> Finding {
    let mut finding = Finding::new_tool(
        "owned-page-fixture",
        name,
        "source.rs",
        1,
        None,
        severity,
        &format!("Labeled {name} observation"),
    );
    finding.identity_id = Some(format!("fi_owned_page_{name}"));
    finding.identity_basis = Some(FindingIdentityBasis::ExactProducerFingerprint);
    finding
}

fn fixture(root: &Path) -> FindingStore {
    let store = super::retained_attempts::retained_fixture(root);
    store
        .record_run_started("outside-history", root, "completed")
        .unwrap();
    let outside = (0..500)
        .map(|n| row(&format!("outside.{n}"), Severity::Critical))
        .collect::<Vec<_>>();
    store.insert_findings("outside-history", &outside).unwrap();
    let earlier = row("canceled-member", Severity::Info);
    store.insert_finding("run-trial-1-a1", &earlier).unwrap();
    store
        .insert_finding("run-trial-1-a2", &row("completed-member", Severity::Info))
        .unwrap();
    store
        .record_run_started("run-trial-3-a1", root, "completed")
        .unwrap();
    store
        .insert_finding("run-trial-3-a1", &row("superseded-member", Severity::Info))
        .unwrap();
    store.insert_finding("outside-history", &earlier).unwrap();
    store
}

fn filter() -> FindingListFilter {
    FindingListFilter::from_tool_input(&json!({"batchId":"batch-test","limit":2})).unwrap()
}

#[test]
fn study_membership_precedes_paging_and_preserves_global_aliases_and_retained_attempts() {
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    let all = store
        .list_findings_filtered(&FindingListFilter::with_limit(500))
        .unwrap();
    assert_eq!(all.count, 503);
    assert!(all
        .findings
        .iter()
        .all(|row| row.severity == Severity::Critical));
    let first = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    assert_eq!(first.page.total, 3);
    assert_eq!(first.report.findings.len(), 2);
    let snapshot = crate::findings::read_finding_page_snapshot(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    assert_eq!(snapshot.page, first);
    let study = snapshot.study.unwrap();
    assert_eq!(study.batch_id, "batch-test");
    assert_eq!(study.rows.len(), 3);
    assert_eq!(study.completed, 3);
    let second = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor: first.page.next_cursor.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(second.report.findings.len(), 1);
    assert!(second.page.next_cursor.is_none());
    let global = store.list_all_findings().unwrap();
    for page in [&first, &second] {
        for (finding, alias) in page.report.findings.iter().zip(&page.report.aliases) {
            assert_eq!(
                crate::findings::resolve_finding_alias(&global, alias)
                    .unwrap()
                    .fingerprint,
                finding.fingerprint
            );
            assert!(finding.severity == Severity::Info);
        }
    }
    let back = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor: second.page.previous_cursor,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(back.report, first.report);
}

#[test]
fn shared_dispatch_declares_study_membership_and_rejects_ambiguous_filters() {
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = crate::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let result = registry
        .execute_tool(
            "findings:list",
            json!({"batch":"batch-test","limit":500}),
            &ctx,
        )
        .unwrap();
    assert_eq!(result["data"]["batchId"], "batch-test");
    assert_eq!(result["data"]["page"]["total"], 3);
    let parsed = FindingListFilter::from_filter_expression("batch:batch-test limit:2").unwrap();
    assert_eq!(parsed, filter());
    for input in [
        json!({"batchId":"../outside"}),
        json!({"batchId":"a","filter":"batch:b"}),
    ] {
        assert!(registry.execute_tool("findings:list", input, &ctx).is_err());
    }
    assert!(store
        .list_findings_filtered(&filter())
        .unwrap_err()
        .to_string()
        .contains("workspace findings reader"));
}

#[test]
fn queue_accounting_changes_invalidate_a_cursor_without_changing_finding_membership() {
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    let first = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    let path = crate::capabilities::campaign::campaign_queue_path(target.path(), "batch-test");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    queue["jobs"]["trial-003"]["state"] = json!("failed");
    std::fs::write(&path, queue.to_string()).unwrap();
    let error = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor: first.page.next_cursor,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("query changed"), "{error:#}");
    let fresh = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    assert_eq!(fresh.page.total, 3);
}

#[test]
fn oversized_or_missing_study_metadata_never_falls_back_to_the_workspace_ledger() {
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    let plan = crate::capabilities::campaign::campaign_plan_path(target.path(), "batch-test");
    std::fs::File::create(&plan)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    assert!(read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default()
    )
    .is_err());
    std::fs::remove_file(plan).unwrap();
    assert!(read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default()
    )
    .is_err());
    assert_eq!(store.list_all_findings().unwrap().len(), 503);
}

#[test]
#[cfg(unix)]
fn linked_study_metadata_is_refused_without_reading_the_external_file() {
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let marker = outside.path().join("operator.json");
    std::fs::write(&marker, "private-marker-not-read").unwrap();
    let plan = crate::capabilities::campaign::campaign_plan_path(target.path(), "batch-test");
    std::fs::remove_file(&plan).unwrap();
    std::os::unix::fs::symlink(&marker, &plan).unwrap();
    let error = read_finding_page(
        &store,
        &workspace,
        &filter(),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap_err();
    assert!(!format!("{error:#}").contains("private-marker-not-read"));
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "private-marker-not-read"
    );
}

#[test]
fn each_identity_policy_keeps_a_member_reobserved_later_outside_the_study() {
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    for policy in [
        IdentityFoldPolicy::Legacy,
        IdentityFoldPolicy::Safe,
        IdentityFoldPolicy::Aggressive,
    ] {
        let mut selected = filter();
        selected.limit = 500;
        let page = read_finding_page(
            &store,
            &workspace,
            &selected,
            policy,
            &FindingPageRequest::default(),
        )
        .unwrap();
        assert_eq!(page.page.total, 3, "{policy:?}");
        assert!(page
            .report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "canceled-member"
                && finding.scan_id.as_deref() == Some("outside-history")));
    }
}

#[test]
fn a_study_page_keeps_member_decisions_and_does_not_include_outside_decisions() {
    use crate::findings::DismissReason;
    let target = tempfile::tempdir().unwrap();
    let store = fixture(target.path());
    let workspace = crate::WorkspaceTarget::new(target.path()).unwrap();
    let all = store.list_all_findings().unwrap();
    for rule in ["outside.0", "completed-member"] {
        let finding = all.iter().find(|finding| finding.rule_id == rule).unwrap();
        store
            .append_dismissal(
                finding.id.unwrap(),
                DismissReason::FalsePositive,
                "Labeled operator decision on a synthetic observation",
                "operator",
            )
            .unwrap();
    }
    let mut selected = filter();
    selected.limit = 500;
    let page = read_finding_page(
        &store,
        &workspace,
        &selected,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    assert_eq!(page.report.review_decisions.len(), 1);
    assert!(page.report.review_decisions.keys().all(|key| page
        .report
        .findings
        .iter()
        .any(|finding| &finding.fingerprint == key)));
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 2);
}

#[test]
#[ignore = "Writes labeled native reader history only on an explicitly selected owned fixture"]
fn native_study_page_fixture() {
    let root =
        std::path::PathBuf::from(std::env::var_os("KUZUSHI_STUDY_PAGE_FIXTURE_ROOT").unwrap());
    assert_eq!(root.file_name().unwrap(), "fixture-target");
    assert!(root.join(".git").is_dir());
    let store = fixture(&root);
    std::fs::write(
        root.join(".kuzushi/study-page-fixture.json"),
        json!({
            "synthetic":true,"providerRequests":0,"sourceExecuted":false,"findings":503,
            "observations":504,"studyFindings":3,"outsideFindings":500,
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(store.list_all_findings().unwrap().len(), 503);
}
