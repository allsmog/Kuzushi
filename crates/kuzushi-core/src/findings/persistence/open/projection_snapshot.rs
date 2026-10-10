//! A connection-owned, stable read point for multi-query findings projections.
use super::*;

impl FindingStore {
    /// Read related projection queries in one SQLite transaction. Nested
    /// readers join the caller's transaction without closing it. The snapshot
    /// starts at the first query and does not freeze filesystem artifacts.
    /// Callers must only perform reads here; this is not a write-policy gate.
    pub fn with_projection_snapshot<T>(
        &self,
        read: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
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
