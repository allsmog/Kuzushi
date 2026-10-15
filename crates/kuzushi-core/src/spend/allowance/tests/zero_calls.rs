use super::*;

#[test]
fn zero_calls_refuse_every_phase_and_retry_without_reservations() {
    let ledger = fresh(0, 0);
    for work in [
        InvestigationWork::Context,
        InvestigationWork::Scope,
        InvestigationWork::Discovery,
        InvestigationWork::Review,
        InvestigationWork::Report,
        InvestigationWork::Learning,
    ] {
        for request in ["first", "retry"] {
            let error = ledger
                .reserve_provider_call(&call(request, work))
                .unwrap_err();
            assert!(matches!(
                error.downcast_ref(),
                Some(AllowanceError::Exhausted { limit: 0, .. })
            ));
        }
    }
    let snapshot = ledger.allowance_snapshot("study-one").unwrap();
    assert_eq!(snapshot.remaining_calls(), 0);
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.unresolved_calls, 0);
}

#[test]
fn zero_calls_survive_restart_and_concurrent_admission() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.sqlite3");
    SpendLimiter::open(&path)
        .unwrap()
        .approve_allowance(&approval(0, 0))
        .unwrap();
    let workers: Vec<_> = (0..8).map(|_| SpendLimiter::open(&path).unwrap()).collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers.len()));
    let threads: Vec<_> = workers
        .into_iter()
        .enumerate()
        .map(|(index, ledger)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                assert!(ledger
                    .reserve_provider_call(&call(
                        &format!("worker-{index}"),
                        InvestigationWork::Review
                    ))
                    .is_err());
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let snapshot = SpendLimiter::open(path)
        .unwrap()
        .allowance_snapshot("study-one")
        .unwrap();
    assert_eq!(snapshot.limits.max_provider_calls, 0);
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.unresolved_calls, 0);
}

#[test]
fn increasing_zero_requires_a_new_revision_and_keeps_old_bindings_refused() {
    let ledger = fresh(0, 0);
    let mut revised = approval(1, 0);
    assert!(ledger.approve_allowance(&revised).is_err());
    revised.expected_revision = 1;
    ledger.approve_allowance(&revised).unwrap();
    assert!(ledger
        .reserve_provider_call(&call("stale", InvestigationWork::Discovery))
        .is_err());
    let mut current = call("approved", InvestigationWork::Discovery);
    current.expected_revision = 2;
    drop(ledger.reserve_provider_call(&current).unwrap());
    assert_eq!(
        ledger
            .allowance_snapshot("study-one")
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn reducing_to_zero_cannot_erase_used_or_unresolved_calls() {
    for settled in [false, true] {
        let ledger = fresh(1, 0);
        let reservation = ledger
            .reserve_provider_call(&call("used", InvestigationWork::Discovery))
            .unwrap();
        if settled {
            ledger
                .settle_provider_call(reservation, known_cost(0.1))
                .unwrap();
        }
        let mut revised = approval(0, 0);
        revised.expected_revision = 1;
        assert!(ledger.approve_allowance(&revised).is_err());
        assert_eq!(ledger.allowance_snapshot("study-one").unwrap().revision, 1);
    }
}
