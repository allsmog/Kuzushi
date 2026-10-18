use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("lib.rs"),
        "// Owned scope fixture, never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn accepted(workspace: &WorkspaceTarget, id: &str) -> ScanScopeRef {
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let draft = serde_json::from_value(json!({"schemaVersion":1,"scopes":[{
        "id":id,"name":id,"paths":["lib.rs"],"rationale":"Owned historical boundary",
        "sharedDependencies":[],"openQuestions":[]}],"sharedDiscovery":false,"exclusions":[]}))
    .unwrap();
    let created = crate::workspace::create_scan_scope_proposal(&ctx, Some(draft)).unwrap();
    let saved = crate::workspace::accept_scan_scope_proposal(
        &ctx,
        &created.reference,
        crate::workspace::ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    ScanScopeRef {
        proposal: saved.reference,
        scope_id: id.into(),
    }
}

fn rows(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    run: &str,
    scope: Option<&ScanScopeRef>,
    names: &[&str],
) {
    store
        .record_run_started(run, workspace.root(), "owned-policy")
        .unwrap();
    crate::write_run_artifact_json(
        workspace.root(),
        run,
        "input.json",
        "tool input",
        &json!({"scanScopeRef":scope}),
    )
    .unwrap();
    let rows = names
        .iter()
        .map(|name| {
            crate::Finding::new_tool(
                "owned-policy",
                *name,
                "lib.rs",
                1,
                None,
                crate::Severity::Info,
                *name,
            )
        })
        .collect::<Vec<_>>();
    store.insert_findings(run, &rows).unwrap();
}

fn read(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    expression: &str,
    cursor: Option<String>,
) -> Result<FindingListPage> {
    read_finding_page(
        store,
        workspace,
        &FindingListFilter::from_filter_expression(expression)?,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor,
            ..Default::default()
        },
    )
}

#[test]
fn historical_scope_membership_precedes_paging_and_keeps_whole_ledger_aliases() {
    let (_root, workspace, store) = fixture();
    let app = accepted(&workspace, "App");
    let other = accepted(&workspace, "Other");
    rows(
        &store,
        &workspace,
        "app-old",
        Some(&app),
        &["app.one", "app.two", "app.three"],
    );
    rows(
        &store,
        &workspace,
        "other-new",
        Some(&other),
        &["app.one", "other.only"],
    );
    rows(&store, &workspace, "no-scope", None, &["unbound.same.file"]);
    let expression = format!(
        "scope:App scope-record:{} limit:2",
        app.proposal.record_hash
    );
    let first = read(&store, &workspace, &expression, None).unwrap();
    assert_eq!(first.page.total, 3);
    assert_eq!(first.report.findings.len(), 2);
    let second = read(
        &store,
        &workspace,
        &expression,
        first.page.next_cursor.clone(),
    )
    .unwrap();
    assert_eq!(second.report.findings.len(), 1);
    let all = store.list_all_findings().unwrap();
    let shown = first
        .report
        .findings
        .iter()
        .chain(&second.report.findings)
        .collect::<Vec<_>>();
    assert!(shown.iter().all(|row| row.rule_id.starts_with("app.")));
    assert!(
        shown
            .iter()
            .any(|row| row.scan_id.as_deref() == Some("other-new")),
        "Latest representatives must retain older scoped observations"
    );
    for page in [&first, &second] {
        for (finding, alias) in page.report.findings.iter().zip(&page.report.aliases) {
            assert_eq!(
                crate::resolve_finding_alias(&all, alias)
                    .unwrap()
                    .fingerprint,
                finding.fingerprint
            );
        }
    }
    let scope = first.page.scope_filter.unwrap();
    assert_eq!(scope.matched_run_ids, ["app-old"]);
    assert_eq!(scope.unbound_runs, 1);
    assert!(scope.unavailable_runs.is_empty());
    assert_eq!(scope.references, [app]);
    assert_eq!(
        read(&store, &workspace, "scope:app", None)
            .unwrap()
            .page
            .total,
        0,
        "Accepted ids are case sensitive"
    );
}

#[test]
fn scope_and_source_filters_must_match_the_same_observation_run() {
    let (_root, workspace, store) = fixture();
    let app = accepted(&workspace, "app");
    let other = accepted(&workspace, "other");
    rows(
        &store,
        &workspace,
        "earlier",
        Some(&app),
        &["same.identity"],
    );
    rows(
        &store,
        &workspace,
        "later",
        Some(&other),
        &["same.identity"],
    );
    super::super::tests::write_revision(&workspace, "earlier", 'a');
    super::super::tests::write_revision(&workspace, "later", 'b');
    assert_eq!(
        read(
            &store,
            &workspace,
            "scope:app sha:aaaa branch:main dirty:false",
            None
        )
        .unwrap()
        .page
        .total,
        1
    );
    assert_eq!(
        read(&store, &workspace, "scope:app sha:bbbb", None)
            .unwrap()
            .page
            .total,
        0
    );
    assert_eq!(
        read(&store, &workspace, "scope:app run:lat", None)
            .unwrap()
            .page
            .total,
        0
    );
    assert_eq!(
        read(&store, &workspace, "scope:app run:ear", None)
            .unwrap()
            .page
            .total,
        1
    );
    let allowed = vec!["later".to_owned()];
    let observed = store.observed_run_ids(1, &[], Some(&allowed)).unwrap();
    assert_eq!(observed, allowed);
    let filter = FindingListFilter::from_filter_expression("scope:app").unwrap();
    let mut selected = ScopeRunSelection::default();
    for run in observed {
        selected.observe(&workspace, &run, &filter);
    }
    assert!(
        selected.runs.is_empty(),
        "Study membership and scope must share an observation, not merely a consolidated identity"
    );
    assert_eq!(
        store.observed_run_ids(1, &["ear".into()], None).unwrap(),
        ["earlier"]
    );
}

#[test]
fn exact_records_distinguish_same_named_boundaries_and_remain_historical_after_source_drift() {
    let (_root, workspace, store) = fixture();
    let first = accepted(&workspace, "app");
    let second = accepted(&workspace, "app");
    rows(
        &store,
        &workspace,
        "first",
        Some(&first),
        &["first.observation"],
    );
    rows(
        &store,
        &workspace,
        "second",
        Some(&second),
        &["second.observation"],
    );
    std::fs::write(
        workspace.root().join("lib.rs"),
        "// Changed source, never executed.\n",
    )
    .unwrap();
    assert_eq!(
        read(&store, &workspace, "scope:app", None)
            .unwrap()
            .page
            .total,
        2
    );
    let exact = format!("scope:app scope-record:{}", first.proposal.record_hash);
    let page = read(&store, &workspace, &exact, None).unwrap();
    assert_eq!(page.page.total, 1);
    assert_eq!(page.report.findings[0].rule_id, "first.observation");
    assert_eq!(page.page.scope_filter.unwrap().references, [first]);
}

#[test]
fn unavailable_scope_metadata_is_disclosed_and_invalidates_prior_cursors() {
    let (_root, workspace, store) = fixture();
    let app = accepted(&workspace, "app");
    rows(&store, &workspace, "first", Some(&app), &["one", "two"]);
    rows(&store, &workspace, "second", Some(&app), &["three"]);
    let first = read(&store, &workspace, "scope:app limit:1", None).unwrap();
    let input = crate::run_artifact_path(workspace.root(), "second", "input.json");
    std::fs::write(&input, "{}").unwrap();
    assert!(read(
        &store,
        &workspace,
        "scope:app limit:1",
        first.page.next_cursor
    )
    .is_err());
    let current = read(&store, &workspace, "scope:app", None).unwrap();
    assert_eq!(current.page.total, 2);
    assert_eq!(
        current.page.scope_filter.unwrap().unavailable_runs,
        ["second"]
    );
    assert_eq!(
        std::fs::read_to_string(&input).unwrap(),
        "{}",
        "Reading must not repair or reauthenticate changed input"
    );
    assert!(store
        .observed_run_ids(1, &[], None)
        .unwrap_err()
        .to_string()
        .contains("exceeds 1"));
}

#[test]
fn shared_preparation_exposes_scope_options_and_rejects_inexact_record_hashes() {
    let (_root, workspace, store) = fixture();
    let app = accepted(&workspace, "app");
    rows(&store, &workspace, "owned", Some(&app), &["owned.policy"]);
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
            json!({"scope":"app","scope_record":[app.proposal.record_hash]}),
            &ctx,
        )
        .unwrap();
    assert_eq!(result["data"]["page"]["total"], 1);
    assert_eq!(result["data"]["page"]["scopeFilter"]["matchedRuns"], 1);
    assert!(registry
        .execute_tool(
            "findings:list",
            json!({"scope":"app","scopeRecord":"abcd"}),
            &ctx
        )
        .is_err());
    let filter = FindingListFilter::from_filter_expression("scope:app").unwrap();
    assert!(store
        .list_findings_filtered(&filter)
        .unwrap_err()
        .to_string()
        .contains("workspace findings reader"));
}
