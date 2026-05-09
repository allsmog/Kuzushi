use super::super::domain::{QuantileEstimator, STATE_KEY};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub(crate) fn load_quantile(db: &Path, target_p: f32) -> Result<QuantileEstimator> {
    let conn = open_state_conn(db)?;
    let raw: Option<Vec<u8>> = conn
        .query_row(
            "select value from kuzushi_state where key = ?",
            params![STATE_KEY],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(bytes) = raw {
        if let Ok(state) = serde_json::from_slice::<QuantileEstimator>(&bytes) {
            return Ok(state);
        }
    }
    Ok(QuantileEstimator::new(target_p))
}

pub(crate) fn save_quantile(db: &Path, q: &QuantileEstimator) -> Result<()> {
    let conn = open_state_conn(db)?;
    let body = serde_json::to_vec(q).context("serialise quantile state")?;
    conn.execute(
        "insert into kuzushi_state(key, value, updated_at)
         values (?, ?, ?)
         on conflict(key) do update set value = excluded.value, updated_at = excluded.updated_at",
        params![STATE_KEY, body, current_unix_seconds()],
    )?;
    Ok(())
}

fn open_state_conn(db: &Path) -> Result<Connection> {
    let conn = Connection::open(db)?;
    // The kuzushi_state table is created by the spend ledger schema; if
    // a caller uses the classifier without spend, ensure it exists.
    conn.execute_batch(
        r#"
        create table if not exists kuzushi_state (
          key        text    primary key,
          value      blob,
          updated_at integer not null
        );
        "#,
    )?;
    Ok(conn)
}

fn current_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
