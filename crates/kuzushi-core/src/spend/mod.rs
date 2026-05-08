/// Operations that participate in budgeting. Strings are stable: writing to
/// the ledger uses [`Operation::as_db_str`] and reads round-trip through
/// [`Operation::from_db_str`].

/// Handle returned by [`SpendLimiter::deposit`]. Pass to
/// [`SpendLimiter::refund`] to settle the actual cost. The ticket is
/// `Drop`-aware: dropping without a refund settles at the deposited
/// estimate (best-effort logging — no Result from Drop).

/// The ledger. Reads/writes are serialised through a single mutex so that
/// concurrent depositors observe a consistent view of the cap. A SQLite
/// transaction would be slightly faster but the mutex keeps the API clean.

/// Parse a CLI `--budget` flag like `triage=50,deep-audit=200,full-mode=300`
/// into `(Operation, f64)` pairs. Hyphens and underscores are accepted in op
/// names so operators can write `deep-audit` or `deep_audit`.
use anyhow::{Context, Result};
pub(crate) use as_db_str::*;
pub(crate) use drop::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::env;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
mod as_db_str;
mod drop;
mod open;
mod parse_budget_flag;
#[cfg(test)]
mod tests;

pub use as_db_str::Operation;
pub use as_db_str::SpendError;
pub use as_db_str::SpendLimiter;
pub use as_db_str::SpendTicket;
pub use parse_budget_flag::parse_budget_flag;
