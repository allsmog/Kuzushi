use super::AllowanceReservation;
use crate::{runtime::RuntimeCostReport, spend::SpendLimiter};
use anyhow::Result;
use rusqlite::params;

impl SpendLimiter {
    /// Record the receipt without releasing the call slot. Even a failed or
    /// zero-dollar response consumed an approved provider attempt.
    pub fn settle_provider_call(&self, reservation: AllowanceReservation, cost: RuntimeCostReport) -> Result<()> {
        let state = self.lock();
        anyhow::ensure!(reservation.ledger_id == state.ledger_id, "call reservation belongs to another ledger");
        let changed = state.conn.execute(
            "update investigation_call_reservations set settled_at = ?, observed_usd = ?, cost_complete = ?
             where investigation_id = ? and request_id = ? and reservation_id = ? and settled_at is null",
            params![crate::spend::unix_seconds(), cost.observed_usd_if_available(), cost.is_complete(),
                reservation.investigation_id, reservation.request_id, reservation.reservation_id],
        )?;
        anyhow::ensure!(changed == 1, "call reservation is missing, changed, or already settled");
        Ok(())
    }
}
