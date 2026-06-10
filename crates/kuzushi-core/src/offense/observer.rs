//! Live progress for a running chain.
//!
//! The chain and planner call a [`HopObserver`] as each hop starts and lands,
//! so a long autonomous run animates in the Activity view instead of freezing
//! until it returns. The trait is pure — the offense context does not depend
//! on the trace machinery; the module layer implements it over `ctx.trace`.

use super::play::PlayOutcome;

/// Notified as a chain progresses. All methods default to no-ops so callers
/// that do not care about progress can pass [`NoopObserver`].
pub trait HopObserver {
    /// The chain is about to run against `target`.
    fn on_chain_start(&self, _chain: &str, _target: &str) {}
    /// The planner is about to query the model for the next hop.
    fn on_planning(&self, _step_index: usize) {}
    /// A hop finished with `outcome` (landed or missed).
    fn on_hop(&self, _step_index: usize, _outcome: &PlayOutcome) {}
}

/// An observer that records nothing.
pub struct NoopObserver;
impl HopObserver for NoopObserver {}
