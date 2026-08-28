//! Cross-process evidence for the scan-batch storage boundary.

use crate::event_log::{EventKind, EventLog};
use crate::findings::{Finding, FindingStore, Severity};
use crate::workspace::WorkspaceTarget;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_ROLE: &str = "KUZUSHI_TEST_STORAGE_CHILD_ROLE";
const CHILD_ROOT: &str = "KUZUSHI_TEST_STORAGE_CHILD_ROOT";
const CHILD_READY: &str = "KUZUSHI_TEST_STORAGE_CHILD_READY";
const CHILD_GO: &str = "KUZUSHI_TEST_STORAGE_CHILD_GO";
const CHILD_STOP: &str = "KUZUSHI_TEST_STORAGE_CHILD_STOP";
const PAUSE_KIND: &str = "KUZUSHI_TEST_STORAGE_PAUSE_EVENT_KIND";
const PAUSE_MARKER: &str = "KUZUSHI_TEST_STORAGE_PAUSE_MARKER";

#[test]
fn two_process_writers_survive_kill_between_append_and_projection() {
    let fixture = ProcessFixture::new();
    let mut reader = fixture.spawn("reader", &fixture.reader_ready, None);
    let mut first = fixture.spawn("writer-a", &fixture.first_ready, None);
    let mut second = fixture.spawn(
        "writer-b",
        &fixture.second_ready,
        Some(&fixture.pause_marker),
    );
    fixture.release_when_ready();
    assert!(wait_for_file(
        &fixture.pause_marker,
        Duration::from_secs(20)
    ));

    second.kill().expect("kill paused writer child");
    assert!(!second.wait().expect("wait for killed writer").success());
    assert!(first.wait().expect("wait for first writer").success());

    fixture.recover_interrupted_run();
    fixture.assert_recovered_storage();
    std::fs::write(&fixture.stop, "stop").unwrap();
    assert!(reader.wait().expect("wait for reader").success());
    assert!(fixture.reader_refresh_count() > 0);
}

struct ProcessFixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    go: PathBuf,
    stop: PathBuf,
    reader_ready: PathBuf,
    first_ready: PathBuf,
    second_ready: PathBuf,
    pause_marker: PathBuf,
}

impl ProcessFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).unwrap();
        let workspace = WorkspaceTarget::new(&root).unwrap();
        workspace.ensure_state_dir().unwrap();
        drop(FindingStore::open(workspace.findings_db_path()).unwrap());
        Self {
            go: temp.path().join("go"),
            stop: temp.path().join("stop"),
            reader_ready: temp.path().join("reader-ready"),
            first_ready: temp.path().join("first-ready"),
            second_ready: temp.path().join("second-ready"),
            pause_marker: temp.path().join("pause-marker"),
            _temp: temp,
            root,
        }
    }

    fn spawn(&self, role: &str, ready: &Path, pause: Option<&Path>) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "storage_v3::writer_actor::process_stress_tests::storage_process_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ROLE, role)
            .env(CHILD_ROOT, &self.root)
            .env(CHILD_READY, ready)
            .env(CHILD_GO, &self.go)
            .env(CHILD_STOP, &self.stop)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(marker) = pause {
            command
                .env(PAUSE_KIND, EventKind::FindingObserved.as_str())
                .env(PAUSE_MARKER, marker);
        }
        command.spawn().expect("spawn storage helper")
    }

    fn release_when_ready(&self) {
        for marker in [&self.reader_ready, &self.first_ready, &self.second_ready] {
            assert!(wait_for_file(marker, Duration::from_secs(20)));
        }
        std::fs::write(&self.go, "go").unwrap();
    }

    fn recover_interrupted_run(&self) {
        let workspace = WorkspaceTarget::new(&self.root).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_finished("run-b", "failed", 1)
            .expect("restart must replay the committed observation before terminal state");
    }

    fn assert_recovered_storage(&self) {
        let workspace = WorkspaceTarget::new(&self.root).unwrap();
        let log = EventLog::open(workspace.event_log_dir()).unwrap();
        log.verify_chain().expect("event chain must remain valid");
        let events = log.read_all().unwrap();
        let store = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
        assert_eq!(
            store.projection_meta().unwrap().applied_seq,
            events.len() as u64
        );
        assert_eq!(store.list_findings_for_scan_id("run-a").unwrap().len(), 1);
        assert_eq!(store.list_findings_for_scan_id("run-b").unwrap().len(), 1);
        assert_identity_and_run_rows(&workspace.findings_db_path());
    }

    fn reader_refresh_count(&self) -> usize {
        std::fs::read_to_string(self._temp.path().join("reader-count"))
            .unwrap()
            .parse()
            .unwrap()
    }
}

fn assert_identity_and_run_rows(db_path: &Path) {
    let connection = rusqlite::Connection::open(db_path).unwrap();
    let identity_count: i64 = connection
        .query_row("select count(*) from finding_identities", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(identity_count, 2);
    for run_id in ["run-a", "run-b"] {
        let terminal_count: i64 = connection
            .query_row(
                "select count(*) from run_events where run_id = ?1 and event_kind in ('run-completed','run-failed')",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(terminal_count, 1, "one terminal state for {run_id}");
    }
}

#[test]
#[ignore = "subprocess helper launched by the process stress test"]
fn storage_process_child() {
    let Ok(role) = std::env::var(CHILD_ROLE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
    let ready = PathBuf::from(std::env::var_os(CHILD_READY).unwrap());
    let go = PathBuf::from(std::env::var_os(CHILD_GO).unwrap());
    std::fs::write(ready, "ready").unwrap();
    assert!(wait_for_file(&go, Duration::from_secs(20)));
    if role == "reader" {
        refresh_reader(&root);
    } else {
        write_trial(&root, &role);
    }
}

fn write_trial(root: &Path, role: &str) {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let (run_id, line) = if role == "writer-a" {
        ("run-a", 11)
    } else {
        ("run-b", 29)
    };
    store.record_run_started(run_id, root, "running").unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        format!("CWE-89-{role}"),
        format!("src/{role}.rs"),
        line,
        None,
        Severity::High,
        format!("SQL injection found by {role}"),
    );
    store.insert_finding(run_id, &finding).unwrap();
    store.record_run_finished(run_id, "completed", 1).unwrap();
}

fn refresh_reader(root: &Path) {
    let stop = PathBuf::from(std::env::var_os(CHILD_STOP).unwrap());
    let count_path = stop.parent().unwrap().join("reader-count");
    let db_path = WorkspaceTarget::new(root).unwrap().findings_db_path();
    let mut refreshes = 0usize;
    while !stop.exists() {
        let store = FindingStore::open_read_only(&db_path).unwrap();
        let _ = store.list_findings(usize::MAX).unwrap();
        refreshes += 1;
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(count_path, refreshes.to_string()).unwrap();
}

fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let started = Instant::now();
    while !path.exists() && started.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}
