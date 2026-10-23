use super::*;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn commands() -> Vec<WriterCommand> {
    vec![
        WriterCommand::Watcher(WatcherCommand::SnapshotIndexed(SnapshotWrite {
            snapshot_hash: "snap3_test".into(),
            tree_hash: "tree3_test".into(),
            workspace_root_fingerprint: "owned".into(),
            git_commit: None,
            git_branch: None,
            dirty_hash: None,
            index_hash: None,
            config_hash: None,
            actor: "test".into(),
        })),
        WriterCommand::Watcher(WatcherCommand::FileIndexed(FileFactWrite {
            snapshot_hash: "snap3_test".into(),
            path: "owned.rs".into(),
            blob_hash: "blob3_test".into(),
            storage_path: None,
            file_size: 2,
            mtime_ns: None,
            git_blob_oid: None,
            language: None,
            ast_hash: None,
            actor: "test".into(),
        })),
    ]
}

#[test]
fn source_batch_receipts_match_individual_events_and_projection_recovery() {
    let root = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(root.path().join("log"), root.path().join("index.sqlite3")).unwrap();
    writer.projection.conn.execute_batch("create trigger reject_index before insert on indexed_files begin select raise(abort,'test failure'); end;").unwrap();
    assert!(writer.commit_index_chunk(&commands()).is_err());
    assert_eq!(writer.projection.meta().unwrap().applied_seq, 0);
    assert_eq!(writer.log.read_all().unwrap().len(), 2);
    writer
        .projection
        .conn
        .execute_batch("drop trigger reject_index")
        .unwrap();
    let recovered = writer
        .execute_command(WriterCommand::Control(ControlCommand::Barrier))
        .unwrap();
    assert_eq!(recovered.committed_seq, 2);
    let receipts = writer.commit_index_chunk(&commands()).unwrap();
    assert_eq!(
        receipts
            .iter()
            .map(|row| row.committed_seq)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    assert_eq!(
        receipts[1].event_hash,
        writer.log.read_all().unwrap()[3].event_hash.as_str()
    );
}

#[test]
fn source_batches_cannot_append_control_or_finding_commands() {
    let root = tempfile::tempdir().unwrap();
    let mut session =
        StorageWriterSession::open(root.path().join("log"), root.path().join("index.sqlite3"))
            .unwrap();
    let mut input = commands();
    input.push(WriterCommand::Control(ControlCommand::Barrier));
    assert!(session
        .commit_source_index(input, &mut |_| {}, &|| false)
        .is_err());
    assert_eq!(session.writer.log.head_seq().unwrap(), 0);
}

#[test]
fn source_index_can_cancel_while_waiting_for_the_writer_lock() {
    let root = tempfile::tempdir().unwrap();
    let log = root.path().join("log");
    let db = root.path().join("index.sqlite3");
    let _owner = StorageWriter::open(&log, &db).unwrap();
    let probes = std::cell::Cell::new(0);
    let result = StorageWriterActor::commit_source_index(log, db, commands(), &mut |_| {}, &|| {
        let observed = probes.get();
        probes.set(observed + 1);
        observed >= 5
    });
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("lock acquisition was canceled"));
    assert!(probes.get() >= 6);
}

struct PausedChild(Child);
impl Drop for PausedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn source_index_child() {
    let Some(root) = std::env::var_os("KUZUSHI_TEST_SOURCE_INDEX_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    StorageWriterActor::commit_source_index(
        root.join("log"),
        root.join("index.sqlite3"),
        commands(),
        &mut |_| {},
        &|| false,
    )
    .unwrap();
}

#[test]
fn killed_source_batch_replays_every_durable_envelope() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("paused");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage_v3::writer_actor::source_index::tests::source_index_child",
            "--nocapture",
        ])
        .env("KUZUSHI_TEST_SOURCE_INDEX_ROOT", root.path())
        .env("KUZUSHI_TEST_STORAGE_PAUSE_EVENT_KIND", "file-indexed")
        .env("KUZUSHI_TEST_STORAGE_PAUSE_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = PausedChild(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        marker.exists(),
        "source-index child did not reach its journal boundary"
    );
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    let mut writer =
        StorageWriter::open(root.path().join("log"), root.path().join("index.sqlite3")).unwrap();
    let receipt = writer
        .execute_command(WriterCommand::Control(ControlCommand::Barrier))
        .unwrap();
    assert_eq!(receipt.committed_seq, 2);
    writer.log.verify_chain().unwrap();
    let count: i64 = writer
        .projection
        .conn
        .query_row("select count(*) from indexed_files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
