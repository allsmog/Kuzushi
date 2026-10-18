use super::*;

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.rs"), "owned source\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let writer = FindingStore::open(workspace.findings_db_path()).unwrap();
    writer
        .record_run_started("owned-export", workspace.root(), "completed")
        .unwrap();
    (root, workspace, writer)
}

#[test]
fn concurrent_commit_cannot_mix_a_new_finding_into_an_older_export_read() {
    let (_root, workspace, writer) = fixture();
    let result = with_export_revision(&workspace, |reader| {
        assert!(reader.list_all_findings()?.is_empty());
        writer.insert_finding(
            "owned-export",
            &crate::Finding::new_semgrep(
                "owned.rule",
                "owned.rs",
                1,
                None,
                crate::Severity::Low,
                "Labeled concurrent observation",
            ),
        )?;
        assert!(reader.list_all_findings()?.is_empty());
        Ok(())
    });
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("No new export was published"));
    assert_eq!(writer.list_all_findings().unwrap().len(), 1);
    assert_eq!(
        with_export_revision(&workspace, |reader| reader.list_all_findings())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_projection_generation_change_is_not_hidden_by_an_equal_event_sequence() {
    let before = crate::storage_v3::ProjectionMeta {
        applied_seq: 7,
        generation: 1,
    };
    let after = crate::storage_v3::ProjectionMeta {
        applied_seq: 7,
        generation: 2,
    };
    let before = ExportReadRevision {
        projection: before,
        changes: 1,
    };
    let after = ExportReadRevision {
        projection: after,
        changes: 1,
    };
    assert!(require_same_revision(before, after).is_err());
    require_same_revision(before, before).unwrap();
}

#[test]
fn failed_preparation_preserves_its_error_and_releases_the_read_snapshot() {
    let (_root, workspace, writer) = fixture();
    let result: Result<()> = with_export_revision(&workspace, |reader| {
        reader.list_all_findings()?;
        anyhow::bail!("owned export read failure")
    });
    assert_eq!(result.unwrap_err().to_string(), "owned export read failure");
    writer
        .record_run_started("after-failure", workspace.root(), "completed")
        .unwrap();
    with_export_revision(&workspace, |reader| reader.list_all_findings()).unwrap();
}

#[test]
fn commits_outside_finding_events_also_invalidate_the_export_read() {
    let (_root, workspace, _writer) = fixture();
    let writer = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
    writer
        .execute_batch("create table owned_report_marker(value integer)")
        .unwrap();
    let result = with_export_revision(&workspace, |reader| {
        reader.list_all_findings()?;
        let before = reader.projection_meta()?;
        writer.execute("insert into owned_report_marker values (1)", [])?;
        assert_eq!(reader.projection_meta()?, before);
        Ok(())
    });
    assert!(result.unwrap_err().to_string().contains("Findings changed"));
}
