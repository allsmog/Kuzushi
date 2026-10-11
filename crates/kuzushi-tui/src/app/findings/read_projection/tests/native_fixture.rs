//! Explicit owned synthetic-ledger fixtures, never part of the default tests.
use super::*;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(std::env::var("KUZUSHI_REVIEW_SNAPSHOT_FIXTURE_OUT").unwrap())
}

fn row(index: usize) -> Finding {
    Finding::new_tool(
        "fixture",
        &format!("snapshot.{index:04}"),
        "owned.rs",
        1,
        None,
        kuzushi_core::Severity::Low,
        &format!("Synthetic snapshot candidate {index:04}"),
    )
}

#[test]
#[ignore = "explicit owned native ledger preparation only"]
fn prepare_native_review_snapshot_fixture() {
    let root = root();
    std::fs::create_dir_all(&root).unwrap();
    for name in ["app.py", "config.env"] {
        let _ = std::fs::remove_file(root.join(name));
    }
    std::fs::write(
        root.join("owned.rs"),
        "// Owned snapshot fixture; never executed.\n",
    )
    .unwrap();
    std::fs::write(root.join("README.md"), "Synthetic findings for concurrent Review presentation tests. No model, scanner or target execution.\n").unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("snapshot-import", workspace.root(), "completed")
        .unwrap();
    store
        .insert_findings("snapshot-import", &(0..800).map(row).collect::<Vec<_>>())
        .unwrap();
    let ordered = kuzushi_core::sorted_finding_aliases(&store.list_all_findings().unwrap());
    let receipt = serde_json::json!({"findingsAreSynthetic":true,"findingCount":800,
        "selectedAlias":ordered[600].0,"selectedFingerprint":ordered[600].1.fingerprint,
        "selectedId":ordered[600].1.id,"writerFingerprint":ordered[0].1.fingerprint,
        "providerRequests":0,"scannerJobs":0,"sourceExecuted":false});
    std::fs::write(
        root.join("snapshot-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "explicit finite owned writer only"]
fn run_native_review_snapshot_updates() {
    let root = root();
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("snapshot-fixture.json")).unwrap())
            .unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let mut finding = store
        .get_finding_by_fingerprint(receipt["writerFingerprint"].as_str().unwrap())
        .unwrap()
        .unwrap();
    store
        .record_run_started("snapshot-updates", workspace.root(), "running")
        .unwrap();
    for iteration in 0..240 {
        if root.join("stop-snapshot-writer").exists() {
            break;
        }
        finding.message = format!("Synthetic external observation {iteration}");
        store.insert_finding("snapshot-updates", &finding).unwrap();
        record_writer_progress(
            &root,
            iteration + 1,
            store.projection_meta().unwrap().applied_seq,
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    std::fs::write(
        root.join("snapshot-writer-finished"),
        "Owned finite writer stopped.\n",
    )
    .unwrap();
}

fn record_writer_progress(root: &Path, writes: usize, watermark: u64) {
    let receipt =
        serde_json::json!({"writes":writes,"watermark":watermark,"findingsAreSynthetic":true});
    let pending = root.join("snapshot-writer-progress.pending");
    std::fs::write(&pending, serde_json::to_vec(&receipt).unwrap()).unwrap();
    std::fs::rename(pending, root.join("snapshot-writer-progress.json")).unwrap();
}
