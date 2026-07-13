use super::*;

impl SpendLimiter {
    /// Open a ticket with an estimated cost. Fails with [`SpendError`] when
    /// the per-op cap or the global hard ceiling would be exceeded.
    pub fn deposit(&self, op: Operation, est_usd: f64) -> Result<SpendTicket> {
        crate::runtime::RuntimeCost::from_usd(est_usd, "spend deposit estimate")?;
        let state = self.lock();
        enforce_hard_ceiling(&state, est_usd)?;
        enforce_operation_cap(&state, op, est_usd)?;
        insert_spend_ticket(&state, op, est_usd)
    }

    /// Settle a ticket with the actual observed cost. Always succeeds —
    /// over-runs are recorded but never refused (we already did the work).
    pub fn refund(&self, ticket: SpendTicket, actual_usd: f64) -> Result<()> {
        let mut ticket = ticket;
        anyhow::ensure!(
            actual_usd.is_finite() && actual_usd >= 0.0,
            "actual_usd must be a finite non-negative number, got {actual_usd}"
        );
        let state = self.lock();
        let now = unix_seconds();
        let updated = state.conn.execute(
            "update spend_ledger set actual_usd = ?, settled_at = ? where id = ?",
            params![actual_usd, now, ticket.id],
        )?;
        if updated == 0 {
            anyhow::bail!("spend ticket {} not found in ledger", ticket.id);
        }
        ticket.settled = true;
        Ok(())
    }

    /// USD remaining for an op (cap minus committed). Returns `f64::INFINITY`
    /// when no cap is set.
    pub fn remaining(&self, op: Operation) -> Result<f64> {
        let state = self.lock();
        let Some(cap) = state.caps.get(&op).copied() else {
            return Ok(f64::INFINITY);
        };
        let committed = total_committed_for(&state.conn, op)?;
        Ok((cap - committed).max(0.0))
    }

    pub fn total_spent(&self, op: Operation) -> Result<f64> {
        total_committed_for(&self.lock().conn, op)
    }

    pub fn total_spent_all(&self) -> Result<f64> {
        total_committed_all(&self.lock().conn)
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, LimiterState> {
        self.state
            .lock()
            .expect("spend ledger mutex poisoned by panic in another thread")
    }
}

fn enforce_hard_ceiling(state: &LimiterState, request: f64) -> Result<()> {
    let Some(cap) = state.hard_ceiling else {
        return Ok(());
    };
    let committed = total_committed_all(&state.conn)?;
    if checked_commitment(committed, request, "global spend commitment")? > cap {
        return Err(SpendError::HardCeilingExceeded {
            cap,
            committed,
            request,
        }
        .into());
    }
    Ok(())
}

fn enforce_operation_cap(state: &LimiterState, op: Operation, request: f64) -> Result<()> {
    let Some(cap) = state.caps.get(&op).copied() else {
        return Ok(());
    };
    let committed = total_committed_for(&state.conn, op)?;
    if checked_commitment(committed, request, "operation spend commitment")? > cap {
        return Err(SpendError::Exceeded {
            op: op.as_db_str(),
            cap,
            committed,
            request,
        }
        .into());
    }
    Ok(())
}

fn checked_commitment(committed: f64, request: f64, context: &str) -> Result<f64> {
    crate::runtime::RuntimeCost::checked_sum([committed, request], context)
        .map(crate::runtime::RuntimeCost::usd)
}

fn insert_spend_ticket(
    state: &LimiterState,
    op: Operation,
    est_usd: f64,
) -> Result<SpendTicket> {
    state.conn.execute(
        "insert into spend_ledger(op, est_usd, actual_usd, created_at, settled_at)
         values (?, ?, null, ?, null)",
        params![op.as_db_str(), est_usd, unix_seconds()],
    )?;
    Ok(SpendTicket {
        id: state.conn.last_insert_rowid(),
        op,
        est_usd,
        settled: false,
    })
}
