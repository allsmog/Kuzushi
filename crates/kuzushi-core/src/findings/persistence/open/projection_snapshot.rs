//! A connection-owned, stable read point for multi-query findings projections.
use super::*;

impl FindingStore {
    /// Connection-local change marker for commits made by other connections.
    /// Unlike the projection sequence, this also observes accounting writes.
    pub(crate) fn read_change_version(&self) -> Result<i64> {
        self.conn
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .context("Could not read ledger change version")
    }

    /// Read related projection queries in one SQLite transaction. Nested
    /// readers join the caller's transaction without closing it. The snapshot
    /// starts at the first query and does not freeze filesystem artifacts.
    /// Callers must only perform reads here; this is not a write-policy gate.
    pub fn with_projection_snapshot<T>(&self, read: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        if !self.conn.is_autocommit() {
            return read(self);
        }
        let transaction = self
            .conn
            .unchecked_transaction()
            .context("Could not open findings read snapshot")?;
        let value = read(self)?;
        transaction
            .commit()
            .context("Could not close findings read snapshot")?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
