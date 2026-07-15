//! Durable, reference-only workflow attempt ledger.
//!
//! Canonical run artifacts remain payload truth. This module stores only
//! target-bound phase attempts, operator dispositions, and explicit skips so
//! the shell can restore truthful result review after restart.

mod domain;
mod ledger;
mod map_evidence;
mod storage;

pub use domain::*;
pub use ledger::*;
pub use map_evidence::*;
pub use storage::*;

#[cfg(test)]
mod tests;
