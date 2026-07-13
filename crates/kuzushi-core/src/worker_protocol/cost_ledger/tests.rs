use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Barrier};
use std::thread;

const CHILD_TARGET_ENV: &str = "KUZUSHI_COST_LEDGER_TEST_TARGET";
const CHILD_RUN_ENV: &str = "KUZUSHI_COST_LEDGER_TEST_RUN";
const CHILD_INVOCATION_ENV: &str = "KUZUSHI_COST_LEDGER_TEST_INVOCATION";
const CHILD_OUTCOME_ENV: &str = "KUZUSHI_COST_LEDGER_TEST_OUTCOME";
const CHILD_MODE_ENV: &str = "KUZUSHI_COST_LEDGER_TEST_MODE";

#[test]
fn identical_run_ids_are_isolated_by_target() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    let run_id = RunId("same-run".to_string());
    let invocation = InvocationId("inv".to_string());
    let left = RunCostLedgerLease::acquire(left.path(), &run_id).unwrap();
    let right = RunCostLedgerLease::acquire(right.path(), &run_id).unwrap();

    commit(&left, &invocation, 0.75, 1.0);

    assert_eq!(left.run_cost().unwrap(), 0.75);
    assert_eq!(right.run_cost().unwrap(), 0.0);
    assert!(right.reserve(&invocation, 1.0, 1.0).is_ok());
}

#[test]
fn sequential_nonoverlapping_leases_preserve_the_run_cap() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("sequential-run".to_string());
    let first_invocation = InvocationId("first".to_string());
    let second_invocation = InvocationId("second".to_string());

    {
        let first = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
        commit(&first, &first_invocation, 0.75, 1.0);
    }
    let second = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    commit(&second, &second_invocation, 0.25, 1.0);

    assert_eq!(second.run_cost().unwrap(), 1.0);
    assert_eq!(
        second
            .reserve(&InvocationId("third".to_string()), 1.0, 1.0)
            .err()
            .unwrap(),
        KwpError::RuntimeBudget
    );
}

#[test]
fn concurrent_reservations_cannot_claim_the_same_budget() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("concurrent-run".to_string());
    let barrier = Arc::new(Barrier::new(8));
    let threads = (0..8)
        .map(|index| {
            concurrent_reservation(
                target.path().to_path_buf(),
                run_id.clone(),
                Arc::clone(&barrier),
                index,
            )
        })
        .collect::<Vec<_>>();

    let allowed = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|allowed| *allowed)
        .count();
    assert_eq!(allowed, 1);
}

#[test]
fn failed_calls_roll_back_their_reservation() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("rollback-run".to_string());
    let invocation = InvocationId("inv".to_string());
    let lease = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();

    let reservation = lease.reserve(&invocation, 1.0, 1.0).unwrap();
    assert_eq!(
        lease.reserve(&invocation, 1.0, 1.0).err().unwrap(),
        KwpError::RuntimeBudget
    );
    drop(reservation);

    commit(&lease, &invocation, 0.25, 1.0);
    assert_eq!(lease.invocation_cost(&invocation).unwrap(), 0.25);
}

#[test]
fn actual_spend_is_committed_even_when_provider_exceeds_the_reservation() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("overrun".to_string());
    let invocation = InvocationId("inv".to_string());
    let lease = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();

    let committed = lease
        .reserve(&invocation, 0.5, 0.5)
        .unwrap()
        .commit(0.75)
        .unwrap();

    assert!(committed.exceeded_reservation);
    assert_eq!(lease.invocation_cost(&invocation).unwrap(), 0.75);
    assert_eq!(lease.run_cost().unwrap(), 0.75);
}

#[test]
fn provider_overrun_is_charged_before_the_runtime_result_is_denied() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("overrun-denial".to_string());
    let invocation = InvocationId("inv".to_string());
    let lease = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    let reservation = lease.reserve(&invocation, 0.5, 0.5).unwrap();

    assert_eq!(
        super::super::commit_runtime_result(reservation, 0.75, "response").unwrap_err(),
        KwpError::RuntimeBudget
    );
    assert_eq!(lease.run_cost().unwrap(), 0.75);
}

#[test]
fn invalid_provider_cost_keeps_the_reservation_charged() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("invalid-provider-cost".to_string());
    let invocation = InvocationId("inv".to_string());
    let lease = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();

    assert!(lease
        .reserve(&invocation, 1.0, 1.0)
        .unwrap()
        .commit(f64::NAN)
        .is_err());
    drop(lease);

    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 1.0);
    assert_eq!(
        reopened
            .reserve(&InvocationId("next".to_string()), 1.0, 1.0)
            .err()
            .unwrap(),
        KwpError::RuntimeBudget
    );
}

#[test]
fn unresolved_success_keeps_conservative_charge_after_reopen() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("unresolved-success".to_string());
    let invocation = InvocationId("unknown-price".to_string());
    {
        let lease = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
        lease
            .reserve(&invocation, 0.75, 0.75)
            .unwrap()
            .retain_unresolved();
        let invocation_report = lease.invocation_cost_report(&invocation).unwrap();
        assert_eq!(invocation_report.observed_usd(), 0.0);
        assert_eq!(invocation_report.exact_usd(), None);
        assert_eq!(invocation_report.unresolved_reserved_usd(), 0.75);
        assert_eq!(lease.run_cost().unwrap(), 0.75);
    }

    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 0.75);
    assert_eq!(
        reopened
            .reserve(&InvocationId("retry".to_string()), 0.75, 0.75)
            .err()
            .unwrap(),
        KwpError::RuntimeBudget
    );
}

#[test]
fn exact_zero_and_sequential_invocations_remain_distinct_from_run_total() {
    let run_id = RunId("ledger-cost-reports".to_string());
    let ledger = RunCostLedgerLease::acquire_legacy(&run_id);
    let zero = InvocationId("zero".to_string());
    let first = InvocationId("first".to_string());
    let second = InvocationId("second".to_string());

    commit(&ledger, &zero, 0.0, 1.0);
    commit(&ledger, &first, 0.1, 1.0);
    commit(&ledger, &second, 0.2, 1.0);

    assert_eq!(
        ledger.invocation_cost_report(&zero).unwrap().exact_usd(),
        Some(0.0)
    );
    assert_eq!(
        ledger.invocation_cost_report(&first).unwrap().exact_usd(),
        Some(0.1)
    );
    assert_eq!(
        ledger.invocation_cost_report(&second).unwrap().exact_usd(),
        Some(0.2)
    );
    let run_cost = ledger.run_cost_report().unwrap().exact_usd().unwrap();
    assert!((run_cost - 0.3).abs() < 1e-9);
}

#[test]
fn durable_receipt_survives_terminal_lease_cleanup() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("cleanup".to_string());
    let invocation = InvocationId("inv".to_string());
    let receipt = durable::receipt_path(target.path(), &run_id);

    {
        let lease = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
        commit(&lease, &invocation, 0.25, 1.0);
    }

    assert!(receipt.is_file());
    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 0.25);
}

#[test]
fn canonical_run_cost_raises_but_never_double_counts_the_durable_total() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("canonical-reconciliation".to_string());
    let invocation = InvocationId("inv".to_string());
    {
        let ledger = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
        commit(&ledger, &invocation, 0.25, 1.0);
    }
    write_canonical_run_cost(target.path(), &run_id, 0.75);

    let reconciled = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reconciled.invocation_cost(&invocation).unwrap(), 0.25);
    assert_eq!(reconciled.run_cost().unwrap(), 0.75);
    drop(reconciled);

    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 0.75);
}

#[test]
fn canonical_run_cost_does_not_double_count_an_unresolved_reservation() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("canonical-pending-reconciliation".to_string());
    let ledger = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    commit(&ledger, &InvocationId("committed".to_string()), 0.25, 1.0);
    let pending = ledger
        .reserve(&InvocationId("unresolved".to_string()), 0.75, 1.0)
        .unwrap();
    std::mem::forget(pending);
    assert_eq!(ledger.run_cost().unwrap(), 1.0);
    write_canonical_run_cost(target.path(), &run_id, 1.0);

    let reconciled = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reconciled.run_cost().unwrap(), 1.0);
    drop(reconciled);

    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 1.0);
}

#[test]
fn legacy_unqualified_compatibility_ledger_is_explicitly_not_durable() {
    let run_id = RunId("legacy-only".to_string());
    {
        let legacy = RunCostLedgerLease::acquire_legacy(&run_id);
        commit(&legacy, &InvocationId("first".to_string()), 0.5, 1.0);
        assert!(memory::registry_contains(&run_id));
    }
    assert!(!memory::registry_contains(&run_id));

    let reopened = RunCostLedgerLease::acquire_legacy(&run_id);
    assert_eq!(reopened.run_cost().unwrap(), 0.0);
}

#[test]
fn subprocess_commit_survives_a_fresh_parent_reopen() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("subprocess-reopen".to_string());
    let outcome = target.path().join("child-outcome.txt");
    let mut child = spawn_ledger_child(target.path(), &run_id, "child", &outcome, "commit");
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read_to_string(outcome).unwrap(), "committed");

    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 1.0);
    assert_eq!(
        reopened
            .reserve(&InvocationId("parent".to_string()), 1.0, 1.0)
            .err()
            .unwrap(),
        KwpError::RuntimeBudget
    );
}

#[test]
fn concurrent_subprocesses_observe_one_serializable_total() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("subprocess-concurrent".to_string());
    let left_outcome = target.path().join("left.txt");
    let right_outcome = target.path().join("right.txt");
    let left = spawn_ledger_child(target.path(), &run_id, "left", &left_outcome, "commit");
    let right = spawn_ledger_child(target.path(), &run_id, "right", &right_outcome, "commit");

    let statuses = wait_for_children([left, right]);
    assert!(statuses.into_iter().all(|status| status));
    let mut outcomes = [left_outcome, right_outcome].map(|path| fs::read_to_string(path).unwrap());
    outcomes.sort();
    assert_eq!(outcomes, ["committed", "denied"]);
}

#[test]
fn abandoned_subprocess_reservation_remains_charged_after_restart() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("subprocess-crash".to_string());
    let outcome = target.path().join("crash.txt");
    let mut child = spawn_ledger_child(target.path(), &run_id, "crash", &outcome, "abandon");
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read_to_string(outcome).unwrap(), "abandoned");

    let reopened = RunCostLedgerLease::acquire(target.path(), &run_id).unwrap();
    assert_eq!(reopened.run_cost().unwrap(), 1.0);
    assert_eq!(
        reopened
            .reserve(&InvocationId("retry".to_string()), 1.0, 1.0)
            .err()
            .unwrap(),
        KwpError::RuntimeBudget
    );
}

#[test]
fn corrupt_or_oversized_receipts_fail_closed() {
    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("corrupt".to_string());
    let receipt = durable::receipt_path(target.path(), &run_id);
    drop(RunCostLedgerLease::acquire(target.path(), &run_id).unwrap());

    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&receipt).unwrap()).unwrap();
    value["runId"] = serde_json::json!("different-run");
    fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(RunCostLedgerLease::acquire(target.path(), &run_id).is_err());

    fs::write(&receipt, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(RunCostLedgerLease::acquire(target.path(), &run_id).is_err());
}

#[cfg(unix)]
#[test]
fn receipt_reads_do_not_follow_symlinks() {
    use std::os::unix::fs::symlink;

    let target = tempfile::tempdir().unwrap();
    let run_id = RunId("symlink".to_string());
    let receipt = durable::receipt_path(target.path(), &run_id);
    drop(RunCostLedgerLease::acquire(target.path(), &run_id).unwrap());
    let outside = target.path().join("outside.json");
    fs::write(&outside, fs::read(&receipt).unwrap()).unwrap();
    fs::remove_file(&receipt).unwrap();
    symlink(&outside, &receipt).unwrap();

    assert!(RunCostLedgerLease::acquire(target.path(), &run_id).is_err());
}

#[test]
fn durable_ledger_subprocess_actor() {
    let Ok(target) = std::env::var(CHILD_TARGET_ENV) else {
        return;
    };
    let run_id = RunId(std::env::var(CHILD_RUN_ENV).unwrap());
    let invocation = InvocationId(std::env::var(CHILD_INVOCATION_ENV).unwrap());
    let outcome = PathBuf::from(std::env::var(CHILD_OUTCOME_ENV).unwrap());
    let mode = std::env::var(CHILD_MODE_ENV).unwrap();
    let lease = RunCostLedgerLease::acquire(Path::new(&target), &run_id).unwrap();
    let reservation = lease.reserve(&invocation, 1.0, 1.0);

    let result = match (mode.as_str(), reservation) {
        ("commit", Ok(reservation)) => {
            reservation.commit(1.0).unwrap();
            "committed"
        }
        ("commit", Err(KwpError::RuntimeBudget)) => "denied",
        ("abandon", Ok(reservation)) => {
            std::mem::forget(reservation);
            "abandoned"
        }
        (_, Err(error)) => panic!("unexpected child reservation error: {error}"),
        (unexpected, Ok(_)) => panic!("unexpected child mode: {unexpected}"),
    };
    fs::write(outcome, result).unwrap();
}

fn commit(lease: &RunCostLedgerLease, invocation: &InvocationId, actual_cost: f64, limit: f64) {
    lease
        .reserve(invocation, limit, limit)
        .unwrap()
        .commit(actual_cost)
        .unwrap();
}

fn write_canonical_run_cost(target: &Path, run_id: &RunId, cost_usd: f64) {
    let summary = crate::run_artifacts::RunSummary::running(
        &run_id.0,
        "tool",
        Some("worker-policy:run".to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_cost(Some(cost_usd));
    crate::run_artifacts::write_run_summary(target, &summary).unwrap();
}

fn concurrent_reservation(
    target: PathBuf,
    run_id: RunId,
    barrier: Arc<Barrier>,
    index: usize,
) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        let lease = RunCostLedgerLease::acquire(&target, &run_id).unwrap();
        let result = lease.reserve(&InvocationId(format!("inv-{index}")), 1.0, 1.0);
        let allowed = result.is_ok();
        barrier.wait();
        drop(result);
        allowed
    })
}

fn spawn_ledger_child(
    target: &Path,
    run_id: &RunId,
    invocation: &str,
    outcome: &Path,
    mode: &str,
) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "worker_protocol::cost_ledger::tests::durable_ledger_subprocess_actor",
            "--nocapture",
        ])
        .env(CHILD_TARGET_ENV, target)
        .env(CHILD_RUN_ENV, &run_id.0)
        .env(CHILD_INVOCATION_ENV, invocation)
        .env(CHILD_OUTCOME_ENV, outcome)
        .env(CHILD_MODE_ENV, mode)
        .spawn()
        .unwrap()
}

fn wait_for_children(mut children: [Child; 2]) -> [bool; 2] {
    [
        children[0].wait().unwrap().success(),
        children[1].wait().unwrap().success(),
    ]
}
