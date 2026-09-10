use super::{domain::*, persistence::*};
use crate::spend::SpendLimiter;
use anyhow::Result;
use rusqlite::{params, Connection, TransactionBehavior};

impl SpendLimiter {
    /// Obtain once before a provider attempt, including retries. The durable
    /// row remains committed even when this handle is dropped or cancelled.
    pub fn reserve_provider_call(&self, call: &AllowanceCall) -> Result<AllowanceReservation> {
        call.validate()?;
        let mut state = self.lock();
        let ledger_id = state.ledger_id.clone();
        let transaction = state.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let snapshot = snapshot(&transaction, &call.investigation_id)?;
        validate_admission(&snapshot, call)?;
        let (_, approval) = latest_approval(&transaction, &call.investigation_id)?.expect("snapshot read the approval in this transaction");
        super::work_admission::validate_work_call(&transaction, &approval, call)?;
        ensure_fresh_request(&transaction, call)?;
        let reservation_id = uuid::Uuid::new_v4().to_string();
        insert_reservation(&transaction, call, &reservation_id)?;
        transaction.commit()?;
        Ok(AllowanceReservation {
            ledger_id, investigation_id: call.investigation_id.clone(),
            request_id: call.request_id.clone(), reservation_id,
        })
    }
}

fn validate_admission(snapshot: &AllowanceSnapshot, call: &AllowanceCall) -> Result<()> {
    require_revision(call.expected_revision, snapshot.revision)?;
    if call.model != snapshot.model {
        return Err(AllowanceError::ModelMismatch.into());
    }
    let remaining = if call.work.is_review() {
        snapshot.remaining_calls()
    } else {
        snapshot.remaining_discovery_calls()
    };
    require_remaining_call(snapshot, remaining)
}

fn require_remaining_call(snapshot: &AllowanceSnapshot, remaining: u32) -> Result<()> {
    if remaining == 0 {
        return Err(AllowanceError::Exhausted {
            committed: snapshot.committed_calls,
            limit: snapshot.limits.max_provider_calls,
            protected: snapshot.protected_review_remaining(),
        }.into());
    }
    Ok(())
}

fn ensure_fresh_request(conn: &Connection, call: &AllowanceCall) -> Result<()> {
    let exists: bool = conn.query_row(
        "select exists(select 1 from investigation_call_reservations where investigation_id = ? and request_id = ?)",
        params![call.investigation_id, call.request_id], |row| row.get(0),
    )?;
    if exists {
        return Err(AllowanceError::AlreadyReserved(call.request_id.clone()).into());
    }
    Ok(())
}

fn insert_reservation(conn: &Connection, call: &AllowanceCall, reservation_id: &str) -> Result<()> {
    conn.execute(
        "insert into investigation_call_reservations(investigation_id, request_id, reservation_id,
            revision, call_json, review, created_at) values (?, ?, ?, ?, ?, ?, ?)",
        params![call.investigation_id, call.request_id, reservation_id, call.expected_revision,
            serde_json::to_string(call)?, call.work.is_review(), crate::spend::unix_seconds()],
    )?;
    Ok(())
}
