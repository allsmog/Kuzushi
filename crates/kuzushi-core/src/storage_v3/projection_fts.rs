use anyhow::Result;
use rusqlite::Transaction;

pub(super) fn rebuild_fts_if_available(tx: &Transaction<'_>) -> Result<()> {
    if super::meta_u64(tx, "fts_available").unwrap_or(0) == 0 {
        return Ok(());
    }
    tx.execute(
        "insert into finding_search(finding_search) values('rebuild')",
        [],
    )?;
    Ok(())
}
