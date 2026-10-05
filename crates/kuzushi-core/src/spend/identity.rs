use super::*;

pub(super) fn ledger_identity(conn: &Connection) -> Result<String> {
    conn.execute(
        "insert or ignore into kuzushi_state(key, value, updated_at) values (?, ?, ?)",
        params!["spend_ledger_id", uuid::Uuid::new_v4().to_string(), unix_seconds()],
    )?;
    let id: String = conn.query_row(
        "select value from kuzushi_state where key = 'spend_ledger_id'",
        [],
        |row| row.get(0),
    )?;
    uuid::Uuid::parse_str(&id).context("invalid spend ledger identity")?;
    Ok(id)
}
