use super::*;
use crate::{Finding, Severity, WorkspaceTarget};

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.rs"), "// Owned ledger fixture.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let writer = FindingStore::open(workspace.findings_db_path()).unwrap();
    writer.record_run_started("initial", workspace.root(), "completed").unwrap();
    writer.insert_findings("initial", &[finding(1)]).unwrap();
    let reader = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    (root, workspace, writer, reader)
}

fn finding(index: usize) -> Finding {
    Finding::new_tool("fixture", &format!("snapshot.{index}"), "owned.rs", index as u32, None, Severity::Low, &format!("Synthetic ledger row {index}"))
}

#[test]
fn snapshot_keeps_rows_and_decisions_consistent_while_another_connection_commits() {
    let (_root, workspace, writer, reader) = fixture();
    reader.with_projection_snapshot(|reader| {
        let before = reader.projection_meta()?;
        let rows = reader.list_all_findings()?;
        writer.record_run_started("later", workspace.root(), "completed")?;
        writer.insert_findings("later", &[finding(2)])?;
        writer.append_dismissal(rows[0].id.unwrap(), crate::findings::DismissReason::FalsePositive, "Owned concurrent decision", "operator")?;
        assert_eq!(reader.list_all_findings()?.len(), 1);
        assert!(reader.list_all_review_decisions()?.is_empty());
        assert_eq!(reader.projection_meta()?, before);
        Ok(())
    }).unwrap();
    assert!(reader.conn.is_autocommit());
    assert_eq!(reader.list_all_findings().unwrap().len(), 2);
    assert_eq!(reader.list_all_review_decisions().unwrap().len(), 1);
}

#[test]
fn nested_reader_preserves_the_callers_transaction() {
    let (_root, _workspace, _writer, reader) = fixture();
    let transaction = reader.conn.unchecked_transaction().unwrap();
    let watermark = reader.projection_meta().unwrap();
    reader.with_projection_snapshot(|reader| {
        reader.with_projection_snapshot(|reader| {
            assert_eq!(reader.projection_meta()?, watermark);
            Ok(())
        })
    }).unwrap();
    assert!(!reader.conn.is_autocommit());
    transaction.rollback().unwrap();
    assert!(reader.conn.is_autocommit());
}

#[test]
fn read_failure_releases_the_snapshot_and_preserves_the_original_error() {
    let (_root, workspace, writer, reader) = fixture();
    let result: Result<()> = reader.with_projection_snapshot(|reader| {
        reader.projection_meta()?;
        writer.record_run_started("later", workspace.root(), "completed")?;
        writer.insert_findings("later", &[finding(2)])?;
        anyhow::bail!("Owned reader failure")
    });
    assert_eq!(result.unwrap_err().to_string(), "Owned reader failure");
    assert!(reader.conn.is_autocommit());
    assert_eq!(reader.list_all_findings().unwrap().len(), 2);
}

#[test]
fn panic_releases_the_connection_for_a_later_read() {
    let (_root, _workspace, _writer, reader) = fixture();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<()> = reader.with_projection_snapshot(|reader| {
            reader.projection_meta()?;
            panic!("Owned reader panic");
        });
    }));
    assert!(result.is_err());
    assert!(reader.conn.is_autocommit());
    assert_eq!(reader.list_all_findings().unwrap().len(), 1);
}
