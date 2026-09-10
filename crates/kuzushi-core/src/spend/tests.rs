#[cfg(test)]
mod tests {
    use super::super::*;
    use std::collections::BTreeMap;

    fn fresh() -> SpendLimiter {
        SpendLimiter::open_in_memory().unwrap()
    }

    #[test]
    fn no_cap_reports_infinite_remaining() {
        let s = fresh();
        let r = s.remaining(Operation::Triage).unwrap();
        assert!(r.is_infinite());
    }

    #[test]
    fn deposit_reduces_remaining_until_refund_overrides() {
        let s = fresh();
        s.set_cap(Operation::Triage, 100.0).unwrap();
        assert_eq!(s.remaining(Operation::Triage).unwrap(), 100.0);

        let t = s.deposit(Operation::Triage, 30.0).unwrap();
        assert!((s.remaining(Operation::Triage).unwrap() - 70.0).abs() < 1e-9);
        // Refund with a smaller actual reduces committed.
        s.refund(t, 10.0).unwrap();
        assert!((s.remaining(Operation::Triage).unwrap() - 90.0).abs() < 1e-9);
    }

    #[test]
    fn deposit_rejected_when_cap_would_exceed() {
        let s = fresh();
        s.set_cap(Operation::DeepAudit, 50.0).unwrap();
        let _t1 = s.deposit(Operation::DeepAudit, 30.0).unwrap();
        let err = s
            .deposit(Operation::DeepAudit, 25.0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("budget exceeded"), "{err}");
        assert!(err.contains("deep_audit"), "{err}");
    }

    #[test]
    fn refund_overrun_is_recorded_not_refused() {
        let s = fresh();
        s.set_cap(Operation::DeepAudit, 100.0).unwrap();
        let t = s.deposit(Operation::DeepAudit, 50.0).unwrap();
        // Pretend the call cost more than estimated.
        s.refund(t, 60.0).unwrap();
        assert!((s.total_spent(Operation::DeepAudit).unwrap() - 60.0).abs() < 1e-9);
        // Cap is now under-water — next deposit should reflect that.
        let r = s.remaining(Operation::DeepAudit).unwrap();
        assert!((r - 40.0).abs() < 1e-9);
    }

    #[test]
    fn hard_ceiling_is_global_across_ops() {
        let s = SpendLimiter::open_in_memory_with_hard_ceiling(Some(100.0)).unwrap();
        s.set_cap(Operation::Triage, 1000.0).unwrap();
        s.set_cap(Operation::DeepAudit, 1000.0).unwrap();

        let _t1 = s.deposit(Operation::Triage, 60.0).unwrap();
        let err = s
            .deposit(Operation::DeepAudit, 50.0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("hard ceiling"), "{err}");
    }

    #[test]
    fn open_in_memory_defaults_to_no_hard_ceiling() {
        let s = SpendLimiter::open_in_memory().unwrap();

        assert_eq!(s.hard_ceiling(), None);
    }

    #[test]
    fn caps_persist_across_open() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.sqlite3");
        {
            let s = SpendLimiter::open(&path).unwrap();
            s.set_cap(Operation::FullModeMulti, 200.0).unwrap();
            let t = s.deposit(Operation::FullModeMulti, 30.0).unwrap();
            s.refund(t, 25.0).unwrap();
        }
        let s = SpendLimiter::open(&path).unwrap();
        assert_eq!(s.cap(Operation::FullModeMulti), Some(200.0));
        assert!((s.total_spent(Operation::FullModeMulti).unwrap() - 25.0).abs() < 1e-9);
        assert!((s.remaining(Operation::FullModeMulti).unwrap() - 175.0).abs() < 1e-9);
    }

    #[test]
    fn parse_budget_flag_accepts_hyphen_or_underscore() {
        let parsed = parse_budget_flag("triage=50,deep-audit=200,full_mode_multi=300").unwrap();
        let by_op: BTreeMap<_, _> = parsed.into_iter().collect();
        assert_eq!(by_op[&Operation::Triage], 50.0);
        assert_eq!(by_op[&Operation::DeepAudit], 200.0);
        assert_eq!(by_op[&Operation::FullModeMulti], 300.0);
    }

    #[test]
    fn parse_budget_flag_rejects_unknown_op() {
        let err = parse_budget_flag("unknown_op=10").unwrap_err().to_string();
        assert!(err.contains("unknown_op"), "{err}");
    }

    #[test]
    fn parse_budget_flag_rejects_negative() {
        let err = parse_budget_flag("triage=-5").unwrap_err().to_string();
        assert!(err.contains("non-negative"), "{err}");
    }

    #[test]
    fn unsettled_ticket_drop_leaves_estimate_committed() {
        let s = fresh();
        s.set_cap(Operation::Patch, 100.0).unwrap();
        {
            let _t = s.deposit(Operation::Patch, 40.0).unwrap();
            // _t goes out of scope here without refund.
        }
        let total = s.total_spent(Operation::Patch).unwrap();
        // Estimate stays committed — the budget is held, the row is unsettled.
        assert!((total - 40.0).abs() < 1e-9);
    }

    #[test]
    fn finite_ledger_rows_that_overflow_the_sum_are_rejected() {
        let s = fresh();
        {
            let state = s.lock();
            for _ in 0..2 {
                state
                    .conn
                    .execute(
                        "insert into spend_ledger(op, est_usd, actual_usd, created_at, settled_at) values (?, ?, null, 0, null)",
                        rusqlite::params![Operation::Triage.as_db_str(), f64::MAX],
                    )
                    .unwrap();
            }
        }

        let error = s.total_spent(Operation::Triage).unwrap_err().to_string();

        assert!(error.contains("finite non-negative"), "{error}");
        assert!(s.deposit(Operation::Triage, 1.0).is_ok());
        s.set_cap(Operation::Triage, f64::MAX).unwrap();
        assert!(s.deposit(Operation::Triage, 1.0).is_err());
    }
}

#[cfg(test)]
mod workers {
    use super::super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn independent_connections_reserve_under_one_operation_cap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.sqlite3");
        let owner = SpendLimiter::open(&path).unwrap();
        owner.set_cap(Operation::Triage, 1.0).unwrap();
        let workers: Vec<_> = (0..12).map(|_| SpendLimiter::open(&path).unwrap()).collect();
        let barrier = Arc::new(Barrier::new(workers.len()));
        let threads: Vec<_> = workers.into_iter().map(|worker| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                worker.deposit(Operation::Triage, 1.0).is_ok()
            })
        }).collect();
        let admitted = threads.into_iter().map(|thread| usize::from(thread.join().unwrap())).sum::<usize>();
        assert_eq!(admitted, 1);
        assert_eq!(owner.total_spent_all().unwrap(), 1.0);
    }

    #[test]
    fn admission_and_remaining_observe_other_connections_cap_changes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.sqlite3");
        let owner = SpendLimiter::open(&path).unwrap();
        let worker = SpendLimiter::open(&path).unwrap();
        owner.set_cap(Operation::Triage, 2.0).unwrap();
        assert_eq!(worker.remaining(Operation::Triage).unwrap(), 2.0);
        let _ticket = worker.deposit(Operation::Triage, 1.0).unwrap();
        owner.set_cap(Operation::Triage, 1.0).unwrap();
        assert_eq!(worker.remaining(Operation::Triage).unwrap(), 0.0);
        assert!(worker.deposit(Operation::Triage, 1.0).is_err());
    }

    #[test]
    fn settlement_cannot_overwrite_a_ticket_in_another_ledger() {
        let first = SpendLimiter::open_in_memory().unwrap();
        let second = SpendLimiter::open_in_memory().unwrap();
        let ticket = first.deposit(Operation::Triage, 1.0).unwrap();
        let _other = second.deposit(Operation::Triage, 1.0).unwrap();
        assert!(second.refund(ticket, 0.0).unwrap_err().to_string().contains("another ledger"));
        assert_eq!(first.total_spent_all().unwrap(), 1.0);
        assert_eq!(second.total_spent_all().unwrap(), 1.0);
    }

    #[test]
    fn reopening_preserves_unsettled_tickets_and_allows_explicit_settlement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.sqlite3");
        let first = SpendLimiter::open(&path).unwrap();
        let ticket = first.deposit(Operation::Triage, 1.0).unwrap();
        drop(first);
        let resumed = SpendLimiter::open(&path).unwrap();
        assert_eq!(resumed.total_spent_all().unwrap(), 1.0);
        resumed.refund(ticket, 0.5).unwrap();
        assert_eq!(resumed.total_spent_all().unwrap(), 0.5);
    }

    #[test]
    fn invalid_legacy_ceiling_fails_closed_at_admission() {
        let limiter = SpendLimiter::open_in_memory().unwrap();
        limiter.set_hard_ceiling(Some(f64::NAN));
        assert!(limiter.deposit(Operation::Triage, 1.0).is_err());
        assert_eq!(limiter.total_spent_all().unwrap(), 0.0);
    }
}
