use super::*;
use crate::worker_protocol::{
    kwp_audit_log_integrity, now_unix_ms, open_jsonl_append, read_kwp_audit_log,
    serialize_kwp_audit_record, write_kwp_audit_anchor, AuditDecision, Digest, InvocationId,
    KwpAuditLogBody, KwpAuditLogRecord, ModuleId, RunId, KWP_AUDIT_ANCHOR_FILE,
};
use serde_json::Value;
use std::fs;
use std::io::{Seek, SeekFrom};
use std::process::{Child, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const CHILD_MODE_ENV: &str = "KUZUSHI_AUDIT_TEST_MODE";
const CHILD_TARGET_ENV: &str = "KUZUSHI_AUDIT_TEST_TARGET";
const CHILD_RUN_ENV: &str = "KUZUSHI_AUDIT_TEST_RUN";
const CHILD_OUTCOME_ENV: &str = "KUZUSHI_AUDIT_TEST_OUTCOME";
const CHILD_EFFECT_ENV: &str = "KUZUSHI_AUDIT_TEST_EFFECT";
const CHILD_EVENT_ENV: &str = "KUZUSHI_AUDIT_TEST_EVENT";
const CHILD_DELAY_ENV: &str = "KUZUSHI_AUDIT_TEST_DELAY_MS";

#[test]
fn writer_validates_once_then_does_constant_read_work_for_one_thousand_appends() {
    let fixture = Fixture::new("linear");
    let lease = fixture.acquire();

    for index in 0..1_000 {
        lease
            .append(body(&fixture.run_id, format!("event-{index}")))
            .unwrap();
    }

    let writer = lease.writer.lock().unwrap();
    let open = writer.open.as_ref().unwrap();
    assert_eq!(open.initial_records_read, 0);
    assert_eq!(open.initial_bytes_read, 0);
    drop(writer);
    drop(lease);
    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 1_000);
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
}

#[test]
fn external_truncation_and_same_length_mutation_are_detected() {
    let fixture = Fixture::new("mutation");
    let lease = fixture.acquire();
    lease.append(body(&fixture.run_id, "first")).unwrap();

    let original = fs::read(&fixture.log_path).unwrap();
    fs::write(&fixture.log_path, &original[..original.len() / 2]).unwrap();
    assert!(lease
        .append(body(&fixture.run_id, "after-truncate"))
        .unwrap_err()
        .to_string()
        .contains("changed outside"));
    drop(lease);

    fs::remove_dir_all(&fixture.target).unwrap();
    fs::create_dir_all(&fixture.target).unwrap();
    let lease = fixture.acquire();
    lease.append(body(&fixture.run_id, "first")).unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&fixture.log_path)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b" ").unwrap();
    file.sync_all().unwrap();
    assert!(lease
        .append(body(&fixture.run_id, "after-tamper"))
        .unwrap_err()
        .to_string()
        .contains("changed outside"));
}

#[test]
fn interrupted_append_is_rejected_when_a_new_writer_opens() {
    let fixture = Fixture::new("interrupted");
    let lease = fixture.acquire();
    lease.append(body(&fixture.run_id, "first")).unwrap();
    drop(lease);
    let mut file = open_jsonl_append(&fixture.log_path).unwrap();
    writeln!(file, "{{\"partial\":true}}").unwrap();
    file.sync_all().unwrap();

    let lease = fixture.acquire();
    let error = lease.append(body(&fixture.run_id, "second")).unwrap_err();
    assert!(error.to_string().contains("KWP audit"), "{error}");
}

#[test]
fn valid_looking_unjournaled_tail_is_rejected() {
    let fixture = Fixture::new("unjournaled-tail");
    let lease = fixture.acquire();
    lease.append(body(&fixture.run_id, "first")).unwrap();
    drop(lease);
    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    let record = record_for_body(
        body(&fixture.run_id, "forged-extension"),
        Some(records[0].hash.clone()),
    )
    .unwrap();
    let mut file = open_jsonl_append(&fixture.log_path).unwrap();
    append_line(&mut file, &serialize_kwp_audit_record(&record).unwrap()).unwrap();
    file.sync_all().unwrap();

    let error = fixture
        .acquire()
        .append(body(&fixture.run_id, "second"))
        .unwrap_err();
    assert!(error.to_string().contains("KWP audit"), "{error}");
}

#[test]
fn same_run_writers_share_a_lock_and_unrelated_runs_do_not() {
    let fixture = Fixture::new("shared");
    let same = fixture.acquire();
    let same_again = fixture.acquire();
    assert!(Arc::ptr_eq(&same.writer, &same_again.writer));

    let other = Fixture::new("other").acquire();
    assert!(!Arc::ptr_eq(&same.writer, &other.writer));
    let held = same.writer.lock().unwrap();
    assert!(other.writer.try_lock().is_ok());
    drop(held);
}

#[test]
fn concurrent_same_run_appends_produce_one_valid_chain() {
    let fixture = Arc::new(Fixture::new("concurrent"));
    let threads = (0..8)
        .map(|thread_id| {
            let fixture = Arc::clone(&fixture);
            thread::spawn(move || {
                let lease = fixture.acquire();
                for event_id in 0..20 {
                    lease
                        .append(body(
                            &fixture.run_id,
                            format!("event-{thread_id}-{event_id}"),
                        ))
                        .unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().unwrap();
    }

    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 160);
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
}

#[test]
fn cached_writer_refreshes_after_alternating_subprocess_appends() {
    let fixture = Fixture::new("alternating-processes");
    let parent = fixture.acquire();
    parent.append(body(&fixture.run_id, "parent-0")).unwrap();
    run_append_child(&fixture, "child-1");
    parent.append(body(&fixture.run_id, "parent-2")).unwrap();
    run_append_child(&fixture, "child-3");
    parent.append(body(&fixture.run_id, "parent-4")).unwrap();

    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    let events = records
        .iter()
        .map(|record| record.event.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        events,
        ["parent-0", "child-1", "parent-2", "child-3", "parent-4"]
    );
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
}

#[test]
fn reservation_drop_records_unknown_outcome() {
    let fixture = Fixture::new("reservation-drop");
    let lease = fixture.acquire();
    let reservation = lease
        .reserve_until(
            unknown_outcome_body(&fixture.run_id, "broker.test"),
            Instant::now() + Duration::from_secs(1),
            || false,
        )
        .unwrap();
    drop(reservation);

    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 1);
    assert_unknown_outcome(&records[0], "broker.test");
}

#[test]
fn panic_during_reserved_effect_records_unknown_outcome() {
    let fixture = Fixture::new("reservation-panic");
    let lease = fixture.acquire();
    let reservation = lease
        .reserve_until(
            unknown_outcome_body(&fixture.run_id, "broker.panic"),
            Instant::now() + Duration::from_secs(1),
            || false,
        )
        .unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _reservation = reservation;
        panic!("simulated effect panic");
    }));
    assert!(panic.is_err());

    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 1);
    assert_unknown_outcome(&records[0], "broker.panic");
}

#[test]
fn replacement_journal_failure_finalizes_fallback_unknown_outcome() {
    let fixture = Fixture::new("replacement-failure");
    let lease = fixture.acquire();
    let reservation = lease
        .reserve_until(
            unknown_outcome_body(&fixture.run_id, "broker.effect"),
            Instant::now() + Duration::from_secs(1),
            || false,
        )
        .unwrap();
    fs::write(fixture.target.join("effect-ran"), "yes").unwrap();
    lease.inject_fault(TestAuditFault::AfterReplacement);
    let error = reservation
        .commit(body(&fixture.run_id, "broker.effect"))
        .unwrap_err();
    assert!(error.to_string().contains("replacement-journal"));

    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 1);
    assert_unknown_outcome(&records[0], "broker.effect");
    assert!(!fixture.pending_path().exists());
}

#[test]
fn crash_after_effect_recovers_bound_unknown_outcome() {
    let fixture = Fixture::new("crash-after-effect");
    let effect = fixture.target.join("effect-started");
    let mut child = spawn_audit_child(
        &fixture,
        "crash-after-effect",
        &effect,
        None,
        "broker.fs.write",
        None,
    );
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read_to_string(&effect).unwrap(), "effect-started");

    fixture
        .acquire()
        .append(body(&fixture.run_id, "parent-after-crash"))
        .unwrap();
    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 3);
    assert_unknown_outcome(&records[0], "broker.fs.write");
    assert_eq!(records[1].event, "audit.recovery");
    assert_eq!(records[2].event, "parent-after-crash");
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
}

#[test]
fn timed_reservation_does_not_hang_behind_subprocess_effect() {
    let fixture = Fixture::new("deadline-lock");
    let ready = fixture.target.join("holder-ready");
    let mut holder = spawn_audit_child(&fixture, "hold", &ready, None, "broker.holder", Some(600));
    wait_for_file(&ready);
    let waiter_outcome = fixture.target.join("waiter-outcome");
    let started = Instant::now();
    let mut waiter = spawn_audit_child(
        &fixture,
        "deadline",
        &waiter_outcome,
        None,
        "broker.waiter",
        Some(100),
    );
    assert!(waiter.wait().unwrap().success());
    assert_eq!(fs::read_to_string(waiter_outcome).unwrap(), "deadline");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(holder.wait().unwrap().success());
}

#[test]
fn two_processes_cannot_start_effects_from_one_remaining_audit_slot() {
    let fixture = Fixture::new("last-slot-race");
    fixture.seed_records(4_094);
    let left = fixture.target.join("left-outcome");
    let right = fixture.target.join("right-outcome");
    let left_effect = fixture.target.join("left-effect");
    let right_effect = fixture.target.join("right-effect");
    let left_child = spawn_audit_child(
        &fixture,
        "last-slot",
        &left,
        Some(&left_effect),
        "broker.left",
        Some(75),
    );
    let right_child = spawn_audit_child(
        &fixture,
        "last-slot",
        &right,
        Some(&right_effect),
        "broker.right",
        Some(75),
    );
    wait_for_children([left_child, right_child]);

    let mut outcomes = [left, right].map(|path| fs::read_to_string(path).unwrap());
    outcomes.sort();
    assert_eq!(outcomes, ["committed", "denied"]);
    assert_eq!(
        left_effect.exists() as usize + right_effect.exists() as usize,
        1
    );
    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 4_095);
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
}

#[test]
fn mutation_while_reservation_holds_lock_is_rejected() {
    let fixture = Fixture::new("mutation-under-lock");
    let lease = fixture.acquire();
    lease.append(body(&fixture.run_id, "prefix")).unwrap();
    let reservation = lease
        .reserve_until(
            unknown_outcome_body(&fixture.run_id, "broker.test"),
            Instant::now() + Duration::from_secs(1),
            || false,
        )
        .unwrap();
    let mut bytes = fs::read(&fixture.log_path).unwrap();
    bytes[0] = b' ';
    fs::write(&fixture.log_path, bytes).unwrap();
    let error = reservation
        .commit(body(&fixture.run_id, "broker.test"))
        .unwrap_err();
    assert!(error.to_string().contains("changed outside"), "{error}");
    assert!(fixture.pending_path().is_file());
}

#[test]
fn exact_capacity_recovers_pending_before_log() {
    assert_exact_capacity_recovery(TestAuditFault::AfterPending, false);
}

#[test]
fn exact_capacity_recovers_log_before_anchor() {
    assert_exact_capacity_recovery(TestAuditFault::AfterRecord, false);
}

#[test]
fn exact_capacity_recovers_anchor_before_clear() {
    assert_exact_capacity_recovery(TestAuditFault::AfterAnchor, false);
}

#[test]
fn exact_capacity_retries_failed_recovery_marker_write() {
    assert_exact_capacity_recovery(TestAuditFault::AfterPending, true);
}

#[test]
fn recovery_anchor_before_journal_clear_is_idempotent() {
    let fixture = Fixture::new("recovery-anchor");
    let lease = fixture.acquire();
    lease.inject_fault(TestAuditFault::AfterPending);
    assert!(lease.append(body(&fixture.run_id, "recovered")).is_err());
    lease.inject_fault(TestAuditFault::AfterRecoveryAnchor);
    let error = lease.append(body(&fixture.run_id, "not-yet")).unwrap_err();
    assert!(error.to_string().contains("recovery-anchor"));
    lease
        .append(body(&fixture.run_id, "after-recovery"))
        .unwrap();

    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].event, "recovered");
    assert_eq!(records[1].event, "audit.recovery");
    assert_eq!(records[2].event, "after-recovery");
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
}

#[test]
fn audit_subprocess_actor() {
    let Ok(mode) = std::env::var(CHILD_MODE_ENV) else {
        return;
    };
    let target = PathBuf::from(std::env::var_os(CHILD_TARGET_ENV).unwrap());
    let run_id = std::env::var(CHILD_RUN_ENV).unwrap();
    let outcome = PathBuf::from(std::env::var_os(CHILD_OUTCOME_ENV).unwrap());
    let effect = std::env::var_os(CHILD_EFFECT_ENV).map(PathBuf::from);
    let event = std::env::var(CHILD_EVENT_ENV).unwrap();
    let delay = std::env::var(CHILD_DELAY_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    let fixture = ExternalFixture::new(target, run_id);
    run_child_mode(&fixture, &mode, &outcome, effect.as_deref(), &event, delay);
}

struct Fixture {
    _temp: tempfile::TempDir,
    target: PathBuf,
    run_id: String,
    log_path: PathBuf,
    anchor_path: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join(label);
        fs::create_dir_all(&target).unwrap();
        let run_id = format!("run-{label}-{}", uuid::Uuid::new_v4());
        let log_path = crate::worker_protocol::kwp_audit_log_path(&target, &run_id);
        let anchor_path =
            crate::run_artifacts::run_artifact_path(&target, &run_id, KWP_AUDIT_ANCHOR_FILE);
        Self {
            _temp: temp,
            target,
            run_id,
            log_path,
            anchor_path,
        }
    }

    fn acquire(&self) -> KwpAuditWriterLease {
        fs::create_dir_all(&self.target).unwrap();
        KwpAuditWriterLease::acquire(
            &self.target,
            &self.run_id,
            self.log_path.clone(),
            self.anchor_path.clone(),
        )
        .unwrap()
    }

    fn pending_path(&self) -> PathBuf {
        self.log_path.with_file_name(AUDIT_PENDING_FILE)
    }

    fn seed_records(&self, count: usize) {
        fs::create_dir_all(self.log_path.parent().unwrap()).unwrap();
        let mut bytes = Vec::new();
        let mut previous = None;
        for index in 0..count {
            let record = record_for_body(
                body(&self.run_id, format!("seed-{index}")),
                previous.clone(),
            )
            .unwrap();
            bytes.extend_from_slice(&serialize_kwp_audit_record(&record).unwrap());
            bytes.push(b'\n');
            previous = Some(record.hash);
        }
        fs::write(&self.log_path, bytes).unwrap();
        write_kwp_audit_anchor(&self.anchor_path, count, previous.unwrap()).unwrap();
    }
}

struct ExternalFixture {
    target: PathBuf,
    run_id: String,
    log_path: PathBuf,
    anchor_path: PathBuf,
}

impl ExternalFixture {
    fn new(target: PathBuf, run_id: String) -> Self {
        let log_path = crate::worker_protocol::kwp_audit_log_path(&target, &run_id);
        let anchor_path =
            crate::run_artifacts::run_artifact_path(&target, &run_id, KWP_AUDIT_ANCHOR_FILE);
        Self {
            target,
            run_id,
            log_path,
            anchor_path,
        }
    }

    fn acquire(&self) -> KwpAuditWriterLease {
        KwpAuditWriterLease::acquire(
            &self.target,
            &self.run_id,
            self.log_path.clone(),
            self.anchor_path.clone(),
        )
        .unwrap()
    }
}

fn assert_exact_capacity_recovery(fault: TestAuditFault, marker_failure: bool) {
    let fixture = Fixture::new("exact-capacity");
    fixture.seed_records(4_094);
    let lease = fixture.acquire();
    lease.inject_fault(fault);
    assert!(lease
        .append(body(&fixture.run_id, "capacity-commit"))
        .is_err());
    if marker_failure {
        lease.inject_fault(TestAuditFault::RecoveryMarkerWrite);
        let error = lease
            .append(body(&fixture.run_id, "recovery-probe"))
            .unwrap_err();
        assert!(error.to_string().contains("recovery-marker-write"));
    }
    let error = lease
        .append(body(&fixture.run_id, "capacity-probe"))
        .unwrap_err();
    assert_eq!(error, KwpError::quota("audit.log.records"));
    let records = read_kwp_audit_log(&fixture.target, &fixture.run_id).unwrap();
    assert_eq!(records.len(), 4_096);
    assert_eq!(records[4_094].event, "capacity-commit");
    assert_eq!(records[4_095].event, "audit.recovery");
    assert!(kwp_audit_log_integrity(&records).unwrap().ok);
    assert!(!fixture.pending_path().exists());
}

fn assert_unknown_outcome(record: &KwpAuditLogRecord, event: &str) {
    assert_eq!(record.event, event);
    assert_eq!(record.decision, AuditDecision::Deny);
    assert_eq!(
        record.detail.get("status").and_then(Value::as_str),
        Some("unknown-outcome")
    );
}

fn unknown_outcome_body(run_id: &str, event: &str) -> KwpAuditLogBody {
    let mut body = body(run_id, event);
    body.decision = AuditDecision::Deny;
    body.detail = serde_json::json!({
        "status": "unknown-outcome",
        "reason": "broker request interrupted before terminal audit decision"
    });
    body
}

fn run_append_child(fixture: &Fixture, event: &str) {
    let outcome = fixture.target.join(format!("{event}-outcome"));
    let mut child = spawn_audit_child(fixture, "append", &outcome, None, event, None);
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read_to_string(outcome).unwrap(), "committed");
}

fn spawn_audit_child(
    fixture: &Fixture,
    mode: &str,
    outcome: &Path,
    effect: Option<&Path>,
    event: &str,
    delay_ms: Option<u64>,
) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("worker_protocol::audit_writer::tests::audit_subprocess_actor")
        .arg("--nocapture")
        .env(CHILD_MODE_ENV, mode)
        .env(CHILD_TARGET_ENV, &fixture.target)
        .env(CHILD_RUN_ENV, &fixture.run_id)
        .env(CHILD_OUTCOME_ENV, outcome)
        .env(CHILD_EVENT_ENV, event);
    if let Some(effect) = effect {
        command.env(CHILD_EFFECT_ENV, effect);
    }
    if let Some(delay_ms) = delay_ms {
        command.env(CHILD_DELAY_ENV, delay_ms.to_string());
    }
    command.spawn().unwrap()
}

fn run_child_mode(
    fixture: &ExternalFixture,
    mode: &str,
    outcome: &Path,
    effect: Option<&Path>,
    event: &str,
    delay_ms: u64,
) {
    match mode {
        "append" => child_append(fixture, outcome, event),
        "crash-after-effect" => child_crash_after_effect(fixture, outcome, event),
        "hold" => child_hold_reservation(fixture, outcome, event, delay_ms),
        "deadline" => child_deadline(fixture, outcome, event, delay_ms),
        "last-slot" => child_last_slot(fixture, outcome, effect.unwrap(), event, delay_ms),
        other => panic!("unknown audit child mode {other}"),
    }
}

fn child_append(fixture: &ExternalFixture, outcome: &Path, event: &str) {
    fixture
        .acquire()
        .append(body(&fixture.run_id, event))
        .unwrap();
    fs::write(outcome, "committed").unwrap();
}

fn child_crash_after_effect(fixture: &ExternalFixture, outcome: &Path, event: &str) {
    let lease = fixture.acquire();
    let _reservation = lease
        .reserve_until(
            unknown_outcome_body(&fixture.run_id, event),
            Instant::now() + Duration::from_secs(5),
            || false,
        )
        .unwrap();
    fs::write(outcome, "effect-started").unwrap();
    std::process::exit(0);
}

fn child_hold_reservation(fixture: &ExternalFixture, ready: &Path, event: &str, delay_ms: u64) {
    let lease = fixture.acquire();
    let reservation = lease
        .reserve_until(
            unknown_outcome_body(&fixture.run_id, event),
            Instant::now() + Duration::from_secs(5),
            || false,
        )
        .unwrap();
    fs::write(ready, "ready").unwrap();
    thread::sleep(Duration::from_millis(delay_ms));
    reservation.commit(body(&fixture.run_id, event)).unwrap();
}

fn child_deadline(fixture: &ExternalFixture, outcome: &Path, event: &str, deadline_ms: u64) {
    let result = fixture.acquire().append_until(
        body(&fixture.run_id, event),
        Instant::now() + Duration::from_millis(deadline_ms),
        || false,
    );
    let label = match result {
        Err(KwpError::Deadline) => "deadline",
        _ => "unexpected",
    };
    fs::write(outcome, label).unwrap();
}

fn child_last_slot(
    fixture: &ExternalFixture,
    outcome: &Path,
    effect: &Path,
    event: &str,
    delay_ms: u64,
) {
    let lease = fixture.acquire();
    let reservation = lease.reserve_until(
        unknown_outcome_body(&fixture.run_id, event),
        Instant::now() + Duration::from_secs(5),
        || false,
    );
    let Ok(reservation) = reservation else {
        fs::write(outcome, "denied").unwrap();
        return;
    };
    fs::write(effect, "effect-started").unwrap();
    thread::sleep(Duration::from_millis(delay_ms));
    reservation.commit(body(&fixture.run_id, event)).unwrap();
    fs::write(outcome, "committed").unwrap();
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(path.is_file(), "timed out waiting for {}", path.display());
}

fn wait_for_children(children: [Child; 2]) {
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
}

fn body(run_id: &str, event: impl Into<String>) -> KwpAuditLogBody {
    KwpAuditLogBody {
        ts_ms: now_unix_ms(),
        run_id: RunId(run_id.to_string()),
        invocation_id: InvocationId("inv-test".to_string()),
        module_id: ModuleId("module-test".to_string()),
        digest: Digest("sha256:test".to_string()),
        event: event.into(),
        decision: AuditDecision::Allow,
        detail: Value::Null,
        prev: None,
    }
}
