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
}
