//! Per-operation spend ledger with deposit/refund semantics.
//!
//! Mirrors RoboDuck's `SpendLimiter` (`crs/app/helpers.py`): each call to an
//! expensive operation opens a *ticket* with an estimated cost (`deposit`),
//! does the work, and settles the ticket with the actual cost (`refund`).
//! Caps are enforced at deposit time; over-runs are tolerated only on the
//! actual-cost settlement (we never refuse a refund).
//!
//! ## Why deposit/refund and not "just record after"?
//!
//! With a pure post-hoc accounting model, two concurrent expensive calls
//! can each see "remaining = $50" and both proceed, blowing the cap. The
//! deposit holds the budget hostage during work — the second concurrent
//! call sees the post-deposit remaining and fails fast.
//!
//! ## Hard ceiling
//!
//! `KUZUSHI_MAX_USD_PER_RUN` is a per-process kill switch checked before
//! deposit. Once tripped, no further deposits succeed for any op; existing
//! tickets can still refund (we don't strand work in flight).

use std::collections::BTreeMap;
use std::env;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// Operations that participate in budgeting. Strings are stable: writing to
/// the ledger uses [`Operation::as_db_str`] and reads round-trip through
/// [`Operation::from_db_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    Triage,
    ClassifierGate,
    DeepAudit,
    FullModeMulti,
    Patch,
    /// One-turn follow-up that asks the model "did you decline anything?"
    /// after a triage call. Separated from [`Operation::Triage`] so
    /// `kuzushi metrics` can show how much the safety check actually costs.
    RefusalFollowup,
}

impl Operation {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::ClassifierGate => "classifier_gate",
            Self::DeepAudit => "deep_audit",
            Self::FullModeMulti => "full_mode_multi",
            Self::Patch => "patch",
            Self::RefusalFollowup => "refusal_followup",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "triage" => Some(Self::Triage),
            "classifier_gate" => Some(Self::ClassifierGate),
            "deep_audit" => Some(Self::DeepAudit),
            "full_mode_multi" => Some(Self::FullModeMulti),
            "patch" => Some(Self::Patch),
            "refusal_followup" => Some(Self::RefusalFollowup),
            _ => None,
        }
    }

    pub const fn all() -> &'static [Self] {
        &[
            Self::Triage,
            Self::ClassifierGate,
            Self::DeepAudit,
            Self::FullModeMulti,
            Self::Patch,
            Self::RefusalFollowup,
        ]
    }

    /// Default per-call deposit estimate (in USD). Used as a fallback when
    /// no model-specific override matches.
    pub const fn default_deposit_usd(self) -> f64 {
        match self {
            Self::ClassifierGate => 0.001,
            Self::RefusalFollowup => 0.005,
            Self::Triage => 0.010,
            Self::Patch => 0.050,
            Self::DeepAudit => 0.500,
            Self::FullModeMulti => 1.000,
        }
    }
}

/// Cheap multiplier applied to [`Operation::default_deposit_usd`] based on
/// the model substring. Lets `kuzushi metrics` show realistic costs
/// without making operators write a config file: a haiku triage at
/// $0.001 and a sonnet/4o triage at $0.010 are both reasonable
/// approximations of real provider rates.
fn model_cost_multiplier(model: &str) -> f64 {
    let lower = model.to_ascii_lowercase();
    if lower.contains("haiku") || lower.contains("4o-mini") || lower.contains("gpt-5-nano") {
        0.10
    } else if lower.contains("opus") || lower.contains("o1-pro") || lower.contains("o3-pro") {
        4.00
    } else if lower.contains("sonnet")
        || lower.contains("4o")
        || lower.contains("gpt-5")
        || lower.contains("gpt-4")
    {
        1.00
    } else {
        1.00
    }
}

/// Estimate the deposit for a given operation against the configured model.
/// Operators can still override by passing a literal to
/// [`SpendLimiter::deposit`] directly; this is the recommended default.
pub fn estimate_deposit_usd(op: Operation, model: &str) -> f64 {
    op.default_deposit_usd() * model_cost_multiplier(model)
}

/// Handle returned by [`SpendLimiter::deposit`]. Pass to
/// [`SpendLimiter::refund`] to settle the actual cost. The ticket is
/// `Drop`-aware: dropping without a refund settles at the deposited
/// estimate (best-effort logging — no Result from Drop).
#[derive(Debug)]
pub struct SpendTicket {
    id: i64,
    op: Operation,
    est_usd: f64,
    settled: bool,
}

impl SpendTicket {
    pub fn id(&self) -> i64 {
        self.id
    }
    pub fn op(&self) -> Operation {
        self.op
    }
    pub fn est_usd(&self) -> f64 {
        self.est_usd
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error(
        "budget exceeded for {op}: cap=${cap:.2}, committed=${committed:.2}, request=${request:.2}"
    )]
    Exceeded {
        op: &'static str,
        cap: f64,
        committed: f64,
        request: f64,
    },
    #[error(
        "hard ceiling exceeded: cap=${cap:.2}, committed=${committed:.2}, request=${request:.2}"
    )]
    HardCeilingExceeded {
        cap: f64,
        committed: f64,
        request: f64,
    },
}

/// The ledger. Reads/writes are serialised through a single mutex so that
/// concurrent depositors observe a consistent view of the cap. A SQLite
/// transaction would be slightly faster but the mutex keeps the API clean.
pub struct SpendLimiter {
    state: Mutex<LimiterState>,
}

struct LimiterState {
    conn: Connection,
    /// Caps loaded once at init; mutated through [`SpendLimiter::set_cap`].
    caps: BTreeMap<Operation, f64>,
    /// Hard ceiling from `KUZUSHI_MAX_USD_PER_RUN`; `None` = unlimited.
    hard_ceiling: Option<f64>,
}

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

    fn with_connection(conn: Connection) -> Result<Self> {
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

    fn lock(&self) -> std::sync::MutexGuard<'_, LimiterState> {
        self.state
            .lock()
            .expect("spend ledger mutex poisoned by panic in another thread")
    }
}

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

fn ensure_schema(conn: &Connection) -> Result<()> {
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

fn load_caps(conn: &Connection) -> Result<BTreeMap<Operation, f64>> {
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

fn total_committed_for(conn: &Connection, op: Operation) -> Result<f64> {
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

fn total_committed_all(conn: &Connection) -> Result<f64> {
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

fn read_hard_ceiling_from_env() -> Option<f64> {
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

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse a CLI `--budget` flag like `triage=50,deep-audit=200,full-mode=300`
/// into `(Operation, f64)` pairs. Hyphens and underscores are accepted in op
/// names so operators can write `deep-audit` or `deep_audit`.
pub fn parse_budget_flag(value: &str) -> Result<Vec<(Operation, f64)>> {
    let mut out = Vec::new();
    for raw in value.split(',') {
        let pair = raw.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, val) = pair.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("budget pair {pair:?} must use op=USD form (e.g. deep-audit=200)")
        })?;
        let key = key.trim().replace('-', "_").to_lowercase();
        let op = Operation::from_db_str(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown budget op {key:?}; known: triage, classifier_gate, deep_audit, full_mode_multi, patch"
            )
        })?;
        let usd: f64 = val
            .trim()
            .parse()
            .with_context(|| format!("budget value for {key} is not a number: {val:?}"))?;
        anyhow::ensure!(
            usd.is_finite() && usd >= 0.0,
            "budget for {key} must be non-negative, got {usd}"
        );
        out.push((op, usd));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> SpendLimiter {
        SpendLimiter::open_in_memory().unwrap()
    }

    #[test]
    fn no_cap_reports_infinite_remaining() {
        let s = fresh();
        let r = s.remaining(Operation::Triage).unwrap();
        assert!(r.is_infinite());
    }

    #[test]
    fn deposit_reduces_remaining_until_refund_overrides() {
        let s = fresh();
        s.set_cap(Operation::Triage, 100.0).unwrap();
        assert_eq!(s.remaining(Operation::Triage).unwrap(), 100.0);

        let t = s.deposit(Operation::Triage, 30.0).unwrap();
        assert!((s.remaining(Operation::Triage).unwrap() - 70.0).abs() < 1e-9);
        // Refund with a smaller actual reduces committed.
        s.refund(t, 10.0).unwrap();
        assert!((s.remaining(Operation::Triage).unwrap() - 90.0).abs() < 1e-9);
    }

    #[test]
    fn deposit_rejected_when_cap_would_exceed() {
        let s = fresh();
        s.set_cap(Operation::DeepAudit, 50.0).unwrap();
        let _t1 = s.deposit(Operation::DeepAudit, 30.0).unwrap();
        let err = s
            .deposit(Operation::DeepAudit, 25.0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("budget exceeded"), "{err}");
        assert!(err.contains("deep_audit"), "{err}");
    }

    #[test]
    fn refund_overrun_is_recorded_not_refused() {
        let s = fresh();
        s.set_cap(Operation::DeepAudit, 100.0).unwrap();
        let t = s.deposit(Operation::DeepAudit, 50.0).unwrap();
        // Pretend the call cost more than estimated.
        s.refund(t, 60.0).unwrap();
        assert!((s.total_spent(Operation::DeepAudit).unwrap() - 60.0).abs() < 1e-9);
        // Cap is now under-water — next deposit should reflect that.
        let r = s.remaining(Operation::DeepAudit).unwrap();
        assert!((r - 40.0).abs() < 1e-9);
    }

    #[test]
    fn hard_ceiling_is_global_across_ops() {
        let s = fresh();
        s.set_hard_ceiling(Some(100.0));
        s.set_cap(Operation::Triage, 1000.0).unwrap();
        s.set_cap(Operation::DeepAudit, 1000.0).unwrap();

        let _t1 = s.deposit(Operation::Triage, 60.0).unwrap();
        let err = s
            .deposit(Operation::DeepAudit, 50.0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("hard ceiling"), "{err}");
    }

    #[test]
    fn caps_persist_across_open() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.sqlite3");
        {
            let s = SpendLimiter::open(&path).unwrap();
            s.set_cap(Operation::FullModeMulti, 200.0).unwrap();
            let t = s.deposit(Operation::FullModeMulti, 30.0).unwrap();
            s.refund(t, 25.0).unwrap();
        }
        let s = SpendLimiter::open(&path).unwrap();
        assert_eq!(s.cap(Operation::FullModeMulti), Some(200.0));
        assert!((s.total_spent(Operation::FullModeMulti).unwrap() - 25.0).abs() < 1e-9);
        assert!((s.remaining(Operation::FullModeMulti).unwrap() - 175.0).abs() < 1e-9);
    }

    #[test]
    fn parse_budget_flag_accepts_hyphen_or_underscore() {
        let parsed = parse_budget_flag("triage=50,deep-audit=200,full_mode_multi=300").unwrap();
        let by_op: BTreeMap<_, _> = parsed.into_iter().collect();
        assert_eq!(by_op[&Operation::Triage], 50.0);
        assert_eq!(by_op[&Operation::DeepAudit], 200.0);
        assert_eq!(by_op[&Operation::FullModeMulti], 300.0);
    }

    #[test]
    fn parse_budget_flag_rejects_unknown_op() {
        let err = parse_budget_flag("unknown_op=10").unwrap_err().to_string();
        assert!(err.contains("unknown_op"), "{err}");
    }

    #[test]
    fn parse_budget_flag_rejects_negative() {
        let err = parse_budget_flag("triage=-5").unwrap_err().to_string();
        assert!(err.contains("non-negative"), "{err}");
    }

    #[test]
    fn unsettled_ticket_drop_leaves_estimate_committed() {
        let s = fresh();
        s.set_cap(Operation::Patch, 100.0).unwrap();
        {
            let _t = s.deposit(Operation::Patch, 40.0).unwrap();
            // _t goes out of scope here without refund.
        }
        let total = s.total_spent(Operation::Patch).unwrap();
        // Estimate stays committed — the budget is held, the row is unsettled.
        assert!((total - 40.0).abs() < 1e-9);
    }

    #[test]
    fn estimate_deposit_usd_scales_by_model_class() {
        // Cheap models get a 0.10x multiplier so $0.01 triage becomes $0.001.
        assert!(
            (estimate_deposit_usd(Operation::Triage, "anthropic:claude-haiku-4-5") - 0.001).abs()
                < 1e-9
        );
        // Mid-tier models stay at 1.0x.
        assert!(
            (estimate_deposit_usd(Operation::Triage, "anthropic:claude-sonnet-4-6") - 0.010).abs()
                < 1e-9
        );
        // Big models get 4x.
        assert!(
            (estimate_deposit_usd(Operation::Triage, "anthropic:claude-opus-4-7") - 0.040).abs()
                < 1e-9
        );
        // Unknown model strings fall through to 1.0x default.
        assert!(
            (estimate_deposit_usd(Operation::Triage, "unknown:model") - 0.010).abs() < 1e-9
        );
    }

    #[test]
    fn default_deposit_usd_covers_all_operations() {
        for op in Operation::all() {
            assert!(op.default_deposit_usd() > 0.0);
        }
    }
}
