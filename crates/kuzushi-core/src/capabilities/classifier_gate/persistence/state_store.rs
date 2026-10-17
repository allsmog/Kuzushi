use super::super::domain::{QuantileEstimator, STATE_KEY};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub(crate) fn load_quantile(db: &Path, target_p: f32) -> Result<QuantileEstimator> {
    let conn = open_state_conn(db)?;
    if let Some(state) = read_quantile(&conn, &state_key(target_p))? {
        anyhow::ensure!(
            state.p == target_p,
            "Classifier state percentile does not match its key"
        );
        return Ok(state);
    }
    if let Some(state) = read_quantile(&conn, STATE_KEY)? {
        if state.p == target_p {
            return Ok(state);
        }
    }
    Ok(QuantileEstimator::new(target_p))
}

fn state_key(target_p: f32) -> String {
    format!("{STATE_KEY}.p.{:08x}", target_p.to_bits())
}

fn read_quantile(conn: &Connection, key: &str) -> Result<Option<QuantileEstimator>> {
    let raw: Option<Vec<u8>> = conn
        .query_row(
            "select substr(value, 1, 4097) from kuzushi_state where key = ?",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(parse_quantile).transpose()
}

fn parse_quantile(bytes: Vec<u8>) -> Result<QuantileEstimator> {
    anyhow::ensure!(
        bytes.len() <= 4096,
        "Classifier state exceeds the 4 KiB limit"
    );
    let state: QuantileEstimator = serde_json::from_slice(&bytes)
        .context("Classifier state is malformed; saved bytes were preserved")?;
    state.validate_stored()?;
    Ok(state)
}

pub(crate) fn save_quantile(db: &Path, q: &QuantileEstimator) -> Result<()> {
    q.validate_stored()?;
    let conn = open_state_conn(db)?;
    let body = serde_json::to_vec(q).context("serialise quantile state")?;
    conn.execute(
        "insert into kuzushi_state(key, value, updated_at)
         values (?, ?, ?)
         on conflict(key) do update set value = excluded.value, updated_at = excluded.updated_at",
        params![state_key(q.p), body, current_unix_seconds()],
    )?;
    Ok(())
}

fn open_state_conn(db: &Path) -> Result<Connection> {
    let conn = crate::sqlite_connection::open_file(db)?;
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
