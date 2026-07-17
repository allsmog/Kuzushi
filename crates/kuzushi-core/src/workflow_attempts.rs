//! Durable, reference-anchored workflow attempt ledger.
//!
//! Canonical run artifacts remain payload truth. This module stores
//! target-bound phase attempts, reference-only typed receipts, operator
//! dispositions, and explicit skips so the shell can restore truthful result
//! review after restart without copying run payloads into the ledger.

mod domain;
mod ledger;
mod map_evidence;
mod storage;
mod v2;

pub use domain::*;
pub use ledger::*;
pub use map_evidence::*;
pub use storage::*;
pub use v2::*;

#[cfg(test)]
mod tests;
