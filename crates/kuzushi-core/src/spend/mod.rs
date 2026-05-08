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
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod open;
mod parse_budget_flag;
#[cfg(test)]
mod tests;

pub use items_1::Operation;
pub use items_1::SpendError;
pub use items_1::SpendLimiter;
pub use items_1::SpendTicket;
pub use parse_budget_flag::parse_budget_flag;
