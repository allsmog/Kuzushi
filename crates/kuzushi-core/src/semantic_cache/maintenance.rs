use super::{
    database, legacy_cleanup, SemanticCache, SemanticCacheLimits, MS_PER_DAY,
    SEMANTIC_CACHE_RETENTION_DAYS,
};
use anyhow::Result;
use rusqlite::{Connection, TransactionBehavior};
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheMaintenance {
    pub entries: u64,
    pub payload_bytes: u64,
    pub reclaimed_payload_bytes: u64,
    pub reclaimed_legacy_bytes: u64,
    pub quota_pressure: bool,
    pub pending: bool,
}

impl SemanticCache {
    /// Indexed eviction visits at most 64 entries and legacy cleanup at most
    /// 64 directory entries per pass. A crash never postpones unfinished work.
    pub fn maintain(&self) -> Result<CacheMaintenance> {
        self.maintain_at(crate::fs_atomic::now_ms())
    }

    pub(super) fn maintain_at(&self, now_ms: u64) -> Result<CacheMaintenance> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cutoff = retention_cutoff(now_ms);
        let reclaimed_payload_bytes = evict_expired(&transaction, cutoff)?;
        let (reclaimed_legacy_bytes, legacy_pending) =
            legacy_cleanup::prune_batch(&self.root, &transaction)?;
        let pending = legacy_pending || database::has_expired(&transaction, cutoff)?;
        let (entries, payload_bytes) = database::totals(&transaction)?;
        record_completed_prune(&transaction, now_ms, pending)?;
        transaction.commit()?;
        connection.pragma_update(None, "incremental_vacuum", 32)?;
        Ok(CacheMaintenance {
            entries,
            payload_bytes,
            reclaimed_payload_bytes,
            reclaimed_legacy_bytes,
            quota_pressure: !self.limits.admits(entries + 1, payload_bytes + 1),
            pending,
        })
    }
}

pub(super) fn retention_cutoff(now_ms: u64) -> u64 {
    now_ms.saturating_sub(SEMANTIC_CACHE_RETENTION_DAYS * MS_PER_DAY)
}

fn record_completed_prune(connection: &Connection, now_ms: u64, pending: bool) -> Result<()> {
    if !pending {
        connection.execute(
            "UPDATE cache_state SET last_prune_ms=?1 WHERE id=1",
            [database::sql_integer(now_ms)?],
        )?;
    }
    Ok(())
}

fn evict_expired(connection: &Connection, cutoff: u64) -> Result<u64> {
    let mut reclaimed = 0;
    for key in database::oldest(connection, cutoff)? {
        reclaimed += database::remove(connection, &key)?;
    }
    Ok(reclaimed)
}

pub(super) fn make_room(
    connection: &Connection,
    limits: SemanticCacheLimits,
    bytes: u64,
) -> Result<bool> {
    if fits(connection, limits, bytes)? {
        return Ok(true);
    }
    for key in database::oldest(connection, i64::MAX as u64)? {
        database::remove(connection, &key)?;
        if fits(connection, limits, bytes)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn fits(connection: &Connection, limits: SemanticCacheLimits, bytes: u64) -> Result<bool> {
    let (entries, stored_bytes) = database::totals(connection)?;
    Ok(limits.admits(
        entries.saturating_add(1),
        stored_bytes.saturating_add(bytes),
    ))
}
