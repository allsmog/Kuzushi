use super::*;
use crate::{RunSummary, RunTargetGitMetadata, Severity};

fn fixture(count: usize) -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("lib.rs"),
        "// Benign labeled fixture; never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("fixture-a", workspace.root(), "completed")
        .unwrap();
    let rows = (0..count)
        .map(|index| {
            Finding::new_tool(
                "fixture",
                &format!("page.{index:04}"),
                "lib.rs",
                1,
                None,
                Severity::Low,
                &format!("Synthetic candidate {index:04}"),
            )
        })
        .collect::<Vec<_>>();
    store.insert_findings("fixture-a", &rows).unwrap();
    (root, workspace, store)
}

fn read(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    size: usize,
    cursor: Option<String>,
) -> Result<FindingListPage> {
    read_finding_page(
        store,
        workspace,
        &FindingListFilter::with_limit(size),
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor,
            anchor: None,
            order: FindingPageOrder::Confidence,
        },
    )
}

#[test]
fn pages_cover_every_matching_finding_once_and_preserve_aliases() {
    let (_root, workspace, store) = fixture(13);
    let complete = store
        .list_findings_filtered(&FindingListFilter::with_limit(500))
        .unwrap();
    let expected = complete
        .findings
        .iter()
        .zip(&complete.aliases)
        .map(|(finding, alias)| (finding.fingerprint.clone(), alias.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut found = BTreeMap::new();
    let mut cursor = None;
    for _ in 0..3 {
        let page = read(&store, &workspace, 5, cursor).unwrap();
        assert_eq!(page.page.total, 13);
        for (finding, alias) in page.report.findings.iter().zip(&page.report.aliases) {
            assert!(found
                .insert(finding.fingerprint.clone(), alias.clone())
                .is_none());
        }
        cursor = page.page.next_cursor;
    }
    assert!(cursor.is_none());
    assert_eq!(found, expected);
}

#[test]
fn exact_file_paths_apply_before_paging_and_bind_the_cursor() {
    let (_root, workspace, store) = fixture(7);
    store
        .insert_findings(
            "fixture-a",
            &[Finding::new_tool(
                "fixture",
                "sibling",
                "lib.rs.backup",
                1,
                None,
                Severity::Low,
                "Different file",
            )],
        )
        .unwrap();
    let mut filter = FindingListFilter::from_tool_input(&serde_json::json!({
        "filePaths":["lib.rs"], "limit":2
    }))
    .unwrap();
    let page = read_finding_page(
        &store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    assert_eq!(page.page.total, 7);
    assert_eq!(page.report.findings.len(), 2);
    assert!(page
        .report
        .findings
        .iter()
        .all(|finding| finding.file_path == "lib.rs"));
    filter.file_paths.push("absent.rs".into());
    let error = read_finding_page(
        &store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest {
            cursor: page.page.next_cursor,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("query changed"), "{error}");
}

#[test]
fn previous_page_returns_the_same_rows() {
    let (_root, workspace, store) = fixture(9);
    let first = read(&store, &workspace, 4, None).unwrap();
    let second = read(&store, &workspace, 4, first.page.next_cursor.clone()).unwrap();
    let back = read(&store, &workspace, 4, second.page.previous_cursor).unwrap();
    assert_eq!(back.report, first.report);
}

#[test]
fn cursor_survives_unrelated_listing_run_bookkeeping() {
    let (_root, workspace, store) = fixture(3);
    let first = read(&store, &workspace, 1, None).unwrap();
    store
        .record_run_started("listing", workspace.root(), "completed")
        .unwrap();
    write_revision(&workspace, "listing", 'b');
    let second = read(&store, &workspace, 1, first.page.next_cursor).unwrap();
    assert_ne!(
        first.report.findings[0].fingerprint,
        second.report.findings[0].fingerprint
    );
    assert!(second.page.watermark > first.page.watermark);
}

#[test]
fn page_reads_share_a_snapshot_without_weakening_later_cursor_validation() {
    let (_root, workspace, writer) = fixture(3);
    let reader = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    let first = reader
        .with_projection_snapshot(|reader| {
            let first = read(reader, &workspace, 1, None)?;
            writer.record_run_started("concurrent", workspace.root(), "completed")?;
            let row = Finding::new_tool(
                "fixture",
                "page.later",
                "lib.rs",
                1,
                None,
                Severity::Low,
                "Synthetic later row",
            );
            writer.insert_findings("concurrent", &[row])?;
            let second = read(reader, &workspace, 1, first.page.next_cursor.clone())?;
            assert_eq!(second.page.total, 3);
            assert_eq!(second.page.watermark, first.page.watermark);
            assert_ne!(
                second.report.findings[0].fingerprint,
                first.report.findings[0].fingerprint
            );
            Ok(first)
        })
        .unwrap();
    assert!(read(&reader, &workspace, 1, first.page.next_cursor).is_err());
    assert_eq!(read(&reader, &workspace, 1, None).unwrap().page.total, 4);
}

#[test]
fn cursor_rejects_a_new_review_decision_on_the_same_generation() {
    let (_root, workspace, store) = fixture(3);
    let first = read(&store, &workspace, 1, None).unwrap();
    store
        .append_dismissal(
            first.report.findings[0].id.unwrap(),
            crate::findings::DismissReason::FalsePositive,
            "Owned review change",
            "operator",
        )
        .unwrap();
    assert!(read(&store, &workspace, 1, first.page.next_cursor).is_err());
}

#[test]
fn cursor_rejects_changed_suppression_state_on_the_same_generation() {
    let (_root, workspace, store) = fixture(3);
    let first = read(&store, &workspace, 1, None).unwrap();
    let registry = crate::modules::ModuleRegistry::with_v2_builtins();
    let config = crate::V2Config::default();
    let ctx = crate::modules::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry.prepare_dispatch_input("suppress:add", serde_json::json!({
        "finding": first.report.findings[0].fingerprint, "reason": "false-positive", "statement": "Owned lifecycle change",
    }), &ctx, None).unwrap().authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert!(read(&store, &workspace, 1, first.page.next_cursor).is_err());
}

#[test]
fn provenance_cursor_tracks_only_runs_that_supply_the_matching_findings() {
    let (_root, workspace, store) = fixture(3);
    write_revision(&workspace, "fixture-a", 'a');
    let mut filter = FindingListFilter::from_filter_expression("sha:aaaaaaaa").unwrap();
    filter.limit = 1;
    let first = read_finding_page(
        &store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    write_revision(&workspace, "unrelated-listing", 'b');
    let request = FindingPageRequest {
        cursor: Some(
            first
                .page
                .next_cursor
                .expect("three matching findings need a next page"),
        ),
        ..Default::default()
    };
    assert!(read_finding_page(
        &store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        &request
    )
    .is_ok());
    let report =
        matching_report_with_provenance(&store, &workspace, &filter, IdentityFoldPolicy::Legacy)
            .unwrap();
    let mut runs = provenance_runs(&workspace, &filter).unwrap();
    let before = query_binding(
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        FindingPageOrder::Ledger,
        &report,
        &runs,
        None,
    )
    .unwrap();
    runs.get_mut("fixture-a")
        .unwrap()
        .target_git
        .as_mut()
        .unwrap()
        .branch = Some("other-branch".into());
    let changed = query_binding(
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        FindingPageOrder::Ledger,
        &report,
        &runs,
        None,
    )
    .unwrap();
    assert_ne!(before, changed);
}

#[test]
fn cursor_rejects_changed_query_target_and_ledger() {
    let (_root, workspace, store) = fixture(5);
    let token = read(&store, &workspace, 2, None)
        .unwrap()
        .page
        .next_cursor
        .unwrap();
    assert!(read(&store, &workspace, 3, Some(token.clone())).is_err());
    let (_other, other_workspace, other_store) = fixture(5);
    assert!(read(&other_store, &other_workspace, 2, Some(token.clone())).is_err());
    store
        .insert_finding(
            "fixture-a",
            &Finding::new_tool(
                "fixture",
                "additional",
                "lib.rs",
                1,
                None,
                Severity::Low,
                "Synthetic added row",
            ),
        )
        .unwrap();
    assert!(read(&store, &workspace, 2, Some(token))
        .unwrap_err()
        .to_string()
        .contains("reload the first page"));
}

#[test]
fn malformed_and_oversized_cursors_fail_without_repair() {
    let (_root, workspace, store) = fixture(2);
    for cursor in ["not a cursor".to_owned(), "x".repeat(513)] {
        assert!(read(&store, &workspace, 1, Some(cursor)).is_err());
    }
}

#[test]
fn provenance_filter_reaches_a_row_beyond_the_legacy_cap() {
    let (_root, workspace, store) = fixture(1);
    write_revision(&workspace, "fixture-a", 'a');
    store
        .record_run_started("fixture-b", workspace.root(), "completed")
        .unwrap();
    let rows = (0..500)
        .map(|index| {
            Finding::new_tool(
                "fixture",
                &format!("later.{index}"),
                "lib.rs",
                1,
                None,
                Severity::Low,
                "Synthetic later candidate",
            )
        })
        .collect::<Vec<_>>();
    store.insert_findings("fixture-b", &rows).unwrap();
    write_revision(&workspace, "fixture-b", 'b');
    let filter = FindingListFilter::from_filter_expression("sha:aaaaaaaa").unwrap();
    let page = read_finding_page(
        &store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Legacy,
        &FindingPageRequest::default(),
    )
    .unwrap();
    assert_eq!(page.page.total, 1);
    assert_eq!(page.report.findings[0].message, "Synthetic candidate 0000");
}

fn write_revision(workspace: &WorkspaceTarget, run: &str, digit: char) {
    let mut summary = RunSummary::running(
        run,
        "fixture:scan",
        None,
        workspace.root().display().to_string(),
    );
    summary.target_git = Some(RunTargetGitMetadata {
        sha: digit.to_string().repeat(40),
        branch: Some("main".into()),
        dirty: false,
    });
    crate::write_run_summary(workspace.root(), &summary.complete()).unwrap();
}

#[test]
fn zero_limit_does_not_offer_a_nonadvancing_cursor() {
    let (_root, workspace, store) = fixture(2);
    let page = read(&store, &workspace, 0, None).unwrap();
    assert_eq!(page.page.total, 2);
    assert!(page.report.findings.is_empty());
    assert!(page.page.next_cursor.is_none());
}

#[test]
fn confidence_order_is_applied_before_selecting_pages_and_serializing() {
    let (_root, workspace, store) = fixture(2);
    let mut finding = Finding::new_tool(
        "fixture",
        "linked",
        "lib.rs",
        1,
        None,
        Severity::Info,
        "Synthetic linked observation",
    );
    finding.static_proof_state = Some(crate::StaticProofState::SourceSinkLinked);
    store.insert_finding("fixture-a", &finding).unwrap();
    let page = read(&store, &workspace, 1, None).unwrap();
    assert_eq!(page.report.findings[0].rule_id, "linked");
    assert_eq!(
        page.to_tool_json()
            .pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("linked")
    );
}

#[test]
fn anchors_preserve_a_finding_after_the_ledger_changes() {
    let (_root, workspace, store) = fixture(8);
    let second = read(
        &store,
        &workspace,
        3,
        read(&store, &workspace, 3, None).unwrap().page.next_cursor,
    )
    .unwrap();
    let anchor = second.page.anchors[0].clone();
    store
        .insert_finding(
            "fixture-a",
            &Finding::new_tool(
                "fixture",
                "added",
                "lib.rs",
                1,
                None,
                Severity::Critical,
                "Synthetic added observation",
            ),
        )
        .unwrap();
    let request = FindingPageRequest {
        anchor: Some(anchor.clone()),
        order: FindingPageOrder::Confidence,
        ..Default::default()
    };
    let page = read_finding_page(
        &store,
        &workspace,
        &FindingListFilter::with_limit(3),
        IdentityFoldPolicy::Legacy,
        &request,
    )
    .unwrap();
    assert!(page.page.anchors.contains(&anchor));
}

#[test]
fn returned_continuity_anchor_follows_a_replaced_generation_inside_the_same_query() {
    let (_root, workspace, store) = fixture(8);
    let first = read(&store, &workspace, 3, None).unwrap();
    let second = read(&store, &workspace, 3, first.page.next_cursor).unwrap();
    let original = second.report.findings[0].clone();
    let anchor = second.page.continuity_anchors[0].clone();
    std::fs::write(
        workspace.root().join("lib.rs"),
        "// New owned source revision, never executed.\n",
    )
    .unwrap();
    store
        .record_run_started("fixture-b", workspace.root(), "completed")
        .unwrap();
    store.insert_finding("fixture-b", &original).unwrap();
    let request = FindingPageRequest {
        anchor: Some(anchor),
        order: FindingPageOrder::Confidence,
        ..Default::default()
    };
    let page = read_finding_page(
        &store,
        &workspace,
        &FindingListFilter::with_limit(3),
        IdentityFoldPolicy::Legacy,
        &request,
    )
    .unwrap();
    let replacement = page
        .report
        .findings
        .iter()
        .find(|row| row.identity_id == original.identity_id)
        .unwrap();
    assert_ne!(replacement.id, original.id);
    assert_eq!(replacement.fingerprint, original.fingerprint);
    assert_eq!(page.page.offset, 3);
    let excluded = FindingListFilter::from_filter_expression("name:nonexistent limit:3").unwrap();
    let error = read_finding_page(
        &store,
        &workspace,
        &excluded,
        IdentityFoldPolicy::Legacy,
        &request,
    )
    .unwrap_err();
    assert!(error.is::<FindingPageAnchorMissing>());
}

#[test]
fn missing_anchor_is_distinct_from_invalid_cursor() {
    let (_root, workspace, store) = fixture(2);
    let missing = FindingPageRequest {
        anchor: Some("generation:99999".into()),
        ..Default::default()
    };
    let error = read_finding_page(
        &store,
        &workspace,
        &FindingListFilter::with_limit(2),
        IdentityFoldPolicy::Legacy,
        &missing,
    )
    .unwrap_err();
    assert!(error.is::<FindingPageAnchorMissing>());
    let cursor = FindingPageRequest {
        cursor: Some("invalid".into()),
        ..Default::default()
    };
    let error = read_finding_page(
        &store,
        &workspace,
        &FindingListFilter::with_limit(2),
        IdentityFoldPolicy::Legacy,
        &cursor,
    )
    .unwrap_err();
    assert!(!error.is::<FindingPageAnchorMissing>());
}

#[test]
fn prepared_dispatch_consumes_cursor_options_and_returns_the_next_page() {
    let (_root, workspace, store) = fixture(4);
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let config = crate::V2Config::default();
    let context = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let first = registry
        .execute_tool(
            "findings:list",
            serde_json::json!({"limit":2,"order":"confidence"}),
            &context,
        )
        .unwrap();
    let cursor = first
        .pointer("/data/page/nextCursor")
        .unwrap()
        .as_str()
        .unwrap();
    let second = registry
        .execute_tool(
            "findings:list",
            serde_json::json!({"limit":2,"order":"confidence","cursor":cursor}),
            &context,
        )
        .unwrap();
    assert_eq!(
        second.pointer("/data/page/offset").and_then(Value::as_u64),
        Some(2)
    );
    assert_ne!(
        first.pointer("/data/findings/0/alias"),
        second.pointer("/data/findings/0/alias")
    );
    assert!(registry
        .execute_tool(
            "findings:list",
            serde_json::json!({"cursor":"bad"}),
            &context
        )
        .is_err());
}
