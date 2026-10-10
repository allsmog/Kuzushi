use super::*;
mod native_fixture;

fn fixture() -> (tempfile::TempDir, ShellApp, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.rs"),
        "// Owned projection fixture.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let writer = FindingStore::open(workspace.findings_db_path()).unwrap();
    writer
        .record_run_started("initial", workspace.root(), "completed")
        .unwrap();
    let row = Finding::new_tool(
        "fixture",
        "snapshot.one",
        "owned.rs",
        1,
        None,
        kuzushi_core::Severity::Low,
        "Synthetic projection row",
    );
    writer.insert_findings("initial", &[row]).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(workspace.root().to_path_buf()));
    (root, app, writer)
}

#[test]
fn complete_projection_keeps_one_watermark_when_rows_and_decisions_change_mid_read() {
    let (root, app, writer) = fixture();
    let request = app.findings_read_request(1, root.path().join("operator"), None);
    let (workspace, reader, durable) =
        open_projection_store(&root.path().to_path_buf(), &request).unwrap();
    let snapshot = reader
        .with_projection_snapshot(|reader| {
            let before = reader.projection_meta()?.applied_seq;
            let first = reader.list_all_findings()?;
            writer.append_dismissal(
                first[0].id.unwrap(),
                kuzushi_core::findings::DismissReason::FalsePositive,
                "Owned external decision",
                "operator",
            )?;
            writer.record_run_started("later", workspace.root(), "completed")?;
            let row = Finding::new_tool(
                "fixture",
                "snapshot.two",
                "owned.rs",
                2,
                None,
                kuzushi_core::Severity::Low,
                "Synthetic later projection row",
            );
            writer.insert_findings("later", &[row])?;
            let snapshot = read_projection_snapshot(
                &workspace,
                reader,
                durable,
                &FindingListFilter::with_limit(500),
                IdentityFoldPolicy::Legacy,
                &request,
            )?;
            assert_eq!(snapshot.watermark, Some(before));
            assert_eq!(snapshot.page.watermark, before);
            assert_eq!(snapshot.report.count, 1);
            assert_eq!(snapshot.corpus.len(), 1);
            assert!(snapshot.review_decisions.is_empty());
            Ok(snapshot)
        })
        .unwrap();
    assert_eq!(snapshot.page.total, 1);
    let current = read_findings_projection(root.path(), &request).unwrap();
    assert_eq!(current.page.total, 2);
    assert_eq!(current.review_decisions.len(), 1);
    assert!(current.watermark > snapshot.watermark);
}

#[test]
fn missing_previous_ledger_is_still_an_error_instead_of_an_empty_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    let mut request = app.findings_read_request(1, root.path().join("operator"), None);
    request.expected_watermark = Some(42);
    let error = read_findings_projection(root.path(), &request).unwrap_err();
    assert!(error
        .to_string()
        .contains("Previously loaded findings ledger is unavailable"));
    assert!(!root.path().join(".kuzushi").exists());
}
