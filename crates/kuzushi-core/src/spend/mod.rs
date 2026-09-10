//! Workspace spending records. Deposits check durable operation caps and
//! reserve estimates in one SQLite write transaction across connections.
//! An unsettled ticket retains its estimate after cancellation or restart.
//! Estimates are not enforceable upper bounds on provider charges.
use anyhow::{Context, Result};
pub(crate) use as_db_str::*;
pub(crate) use drop::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
mod as_db_str;
pub mod allowance;
mod drop;
mod identity;
mod open;
mod parse_budget_flag;
#[cfg(test)]
mod tests;

pub use as_db_str::Operation;
pub use as_db_str::SpendError;
pub use as_db_str::SpendLimiter;
pub use as_db_str::SpendTicket;
pub use parse_budget_flag::parse_budget_flag;
