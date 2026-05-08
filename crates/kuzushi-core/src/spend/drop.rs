use super::*;

impl Drop for SpendTicket {
    fn drop(&mut self) {
        // Operators expect a ticket to settle even if the caller forgot to
        // refund (e.g. panic mid-call). We can't return Result from Drop, so
        // we rely on the limiter's mutex serialisation already happening
        // elsewhere — here we just leave the row unsettled (`actual_usd
        // null`). Total-committed math uses COALESCE so the deposit still
        // counts. A periodic janitor could promote unsettled rows older
        // than N hours to actual_usd = est_usd; not needed for v1.
        if !self.settled {
            // Intentionally silent — we don't want runtime drop paths to
            // log to stderr in a CLI.
        }
    }
}

pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        pragma foreign_keys = on;

        create table if not exists spend_ledger (
          id          integer primary key autoincrement,
          op          text    not null,
          est_usd     real    not null,
          actual_usd  real,
          created_at  integer not null,
          settled_at  integer,
          metadata    text
        );
        create index if not exists idx_spend_ledger_op on spend_ledger(op);

        create table if not exists spend_caps (
          op         text    primary key,
          cap_usd    real    not null,
          updated_at integer not null
        );

        create table if not exists kuzushi_state (
          key        text    primary key,
          value      blob,
          updated_at integer not null
        );
        "#,
    )?;
    Ok(())
}

pub(crate) fn load_caps(conn: &Connection) -> Result<BTreeMap<Operation, f64>> {
    let mut out = BTreeMap::new();
    let mut stmt = conn.prepare("select op, cap_usd from spend_caps")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
    })?;
    for row in rows {
        let (op_str, cap) = row?;
        if let Some(op) = Operation::from_db_str(&op_str) {
            out.insert(op, cap);
        }
        // Unknown ops in the table are ignored — supports rolling
        // forward/back across schema versions without schema-wedging.
    }
    Ok(out)
}

pub(crate) fn total_committed_for(conn: &Connection, op: Operation) -> Result<f64> {
    // committed = SUM(COALESCE(actual_usd, est_usd))
    // actual_usd takes precedence when known; otherwise the deposit estimate
    // is the conservative committed amount.
    let value: Option<f64> = conn
        .query_row(
            "select sum(coalesce(actual_usd, est_usd)) from spend_ledger where op = ?",
            params![op.as_db_str()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(value.unwrap_or(0.0))
}

pub(crate) fn total_committed_all(conn: &Connection) -> Result<f64> {
    let value: Option<f64> = conn
        .query_row(
            "select sum(coalesce(actual_usd, est_usd)) from spend_ledger",
            [],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(value.unwrap_or(0.0))
}

pub(crate) fn read_hard_ceiling_from_env() -> Option<f64> {
    let raw = env::var("KUZUSHI_MAX_USD_PER_RUN").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
}

pub(crate) fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
