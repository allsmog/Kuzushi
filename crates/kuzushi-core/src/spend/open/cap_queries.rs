use super::*;

impl SpendLimiter {
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

    /// Override the hard ceiling for this limiter instance.
    pub fn set_hard_ceiling(&self, value: Option<f64>) {
        self.lock().hard_ceiling = value;
    }
}
