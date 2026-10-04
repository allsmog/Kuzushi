use super::*;

impl SpendLimiter {
    /// Keep uncertain provider exposure reserved, raising it to observed spend.
    pub fn retain_observed(&self, ticket: &SpendTicket, observed_usd: f64) -> Result<()> {
        crate::runtime::RuntimeCost::from_usd(observed_usd, "unresolved observed spend")?;
        let state = self.lock();
        let updated = state.conn.execute(
            "update spend_ledger set est_usd = max(est_usd, ?1) where id = ?2 and settled_at is null",
            params![observed_usd, ticket.id],
        )?;
        anyhow::ensure!(
            updated == 1,
            "unresolved spend ticket is missing or already settled"
        );
        Ok(())
    }

    /// Open a ticket with an estimated cost. Fails with [`SpendError`] when
    /// the per-op cap or the global hard ceiling would be exceeded.
    pub fn deposit(&self, op: Operation, est_usd: f64) -> Result<SpendTicket> {
        crate::runtime::RuntimeCost::from_usd(est_usd, "spend deposit estimate")?;
        let mut state = self.lock();
        let ceiling = state.hard_ceiling;
        let ledger_id = state.ledger_id.clone();
        let transaction = state
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let caps = load_caps(&transaction)?;
        enforce_hard_ceiling(&transaction, ceiling, est_usd)?;
        enforce_operation_cap(&transaction, caps.get(&op).copied(), op, est_usd)?;
        let ticket = insert_spend_ticket(&transaction, ledger_id, op, est_usd)?;
        transaction.commit()?;
        state.caps = caps;
        Ok(ticket)
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
        anyhow::ensure!(ticket.ledger_id == state.ledger_id, "spend ticket belongs to another ledger");
        let now = unix_seconds();
        let updated = state.conn.execute(
            "update spend_ledger set actual_usd = ?, settled_at = ?
             where id = ? and op = ? and est_usd = ? and settled_at is null",
            params![actual_usd, now, ticket.id, ticket.op.as_db_str(), ticket.est_usd],
        )?;
        if updated == 0 {
            anyhow::bail!("spend ticket {} is missing, changed, or already settled", ticket.id);
        }
        ticket.settled = true;
        Ok(())
    }

    /// USD remaining for an op (cap minus committed). Returns `f64::INFINITY`
    /// when no cap is set.
    pub fn remaining(&self, op: Operation) -> Result<f64> {
        let state = self.lock();
        let Some(cap) = load_caps(&state.conn)?.get(&op).copied() else {
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

fn enforce_hard_ceiling(conn: &Connection, ceiling: Option<f64>, request: f64) -> Result<()> {
    let Some(cap) = ceiling else {
        return Ok(());
    };
    crate::runtime::RuntimeCost::from_usd(cap, "spend hard ceiling")?;
    let committed = total_committed_all(conn)?;
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

fn enforce_operation_cap(conn: &Connection, cap: Option<f64>, op: Operation, request: f64) -> Result<()> {
    let Some(cap) = cap else {
        return Ok(());
    };
    let committed = total_committed_for(conn, op)?;
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
    conn: &Connection,
    ledger_id: String,
    op: Operation,
    est_usd: f64,
) -> Result<SpendTicket> {
    conn.execute(
        "insert into spend_ledger(op, est_usd, actual_usd, created_at, settled_at)
         values (?, ?, null, ?, null)",
        params![op.as_db_str(), est_usd, unix_seconds()],
    )?;
    Ok(SpendTicket {
        ledger_id,
        id: conn.last_insert_rowid(),
        op,
        est_usd,
        settled: false,
    })
}
