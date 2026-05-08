use super::prelude::*;
use super::*;

impl SpendLimiter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("could not open spend ledger at {}", path.display()))?;
        Self::with_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("could not open in-memory spend ledger")?;
        Self::with_connection(conn)
    }

    pub(crate) fn with_connection(conn: Connection) -> Result<Self> {
        ensure_schema(&conn)?;
        let caps = load_caps(&conn)?;
        let hard_ceiling = read_hard_ceiling_from_env();
        Ok(Self {
            state: Mutex::new(LimiterState {
                conn,
                caps,
                hard_ceiling,
            }),
        })
    }

    pub fn set_cap(&self, op: Operation, cap_usd: f64) -> Result<()> {
        anyhow::ensure!(
            cap_usd.is_finite() && cap_usd >= 0.0,
            "cap must be a finite non-negative number, got {cap_usd}"
        );
        let mut state = self.lock();
        let now = unix_seconds();
        state.conn.execute(
            "insert into spend_caps(op, cap_usd, updated_at) values(?, ?, ?)
             on conflict(op) do update set cap_usd = excluded.cap_usd, updated_at = excluded.updated_at",
            params![op.as_db_str(), cap_usd, now],
        )?;
        state.caps.insert(op, cap_usd);
        Ok(())
    }

    pub fn cap(&self, op: Operation) -> Option<f64> {
        self.lock().caps.get(&op).copied()
    }

    pub fn caps(&self) -> BTreeMap<Operation, f64> {
        self.lock().caps.clone()
    }

    pub fn hard_ceiling(&self) -> Option<f64> {
        self.lock().hard_ceiling
    }

    /// Override the hard ceiling for the current process. Used by tests; in
    /// production set `KUZUSHI_MAX_USD_PER_RUN`.
    pub fn set_hard_ceiling(&self, value: Option<f64>) {
        self.lock().hard_ceiling = value;
    }

    /// Open a ticket with an estimated cost. Fails with [`SpendError`] when
    /// the per-op cap or the global hard ceiling would be exceeded.
    pub fn deposit(&self, op: Operation, est_usd: f64) -> Result<SpendTicket> {
        anyhow::ensure!(
            est_usd.is_finite() && est_usd >= 0.0,
            "est_usd must be a finite non-negative number, got {est_usd}"
        );
        let state = self.lock();

        // 1. Hard ceiling — checks total committed across every op.
        if let Some(ceiling) = state.hard_ceiling {
            let total_all = total_committed_all(&state.conn)?;
            if total_all + est_usd > ceiling {
                return Err(SpendError::HardCeilingExceeded {
                    cap: ceiling,
                    committed: total_all,
                    request: est_usd,
                }
                .into());
            }
        }

        // 2. Per-op cap.
        if let Some(cap) = state.caps.get(&op).copied() {
            let committed = total_committed_for(&state.conn, op)?;
            if committed + est_usd > cap {
                return Err(SpendError::Exceeded {
                    op: op.as_db_str(),
                    cap,
                    committed,
                    request: est_usd,
                }
                .into());
            }
        }

        // 3. Insert ledger row.
        let now = unix_seconds();
        state.conn.execute(
            "insert into spend_ledger(op, est_usd, actual_usd, created_at, settled_at)
             values (?, ?, null, ?, null)",
            params![op.as_db_str(), est_usd, now],
        )?;
        let id = state.conn.last_insert_rowid();

        Ok(SpendTicket {
            id,
            op,
            est_usd,
            settled: false,
        })
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
