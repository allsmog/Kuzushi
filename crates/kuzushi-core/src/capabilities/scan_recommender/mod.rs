//! Scan recommender: deterministic, reasoned scope×phase scan
//! recommendations folded from the coverage ledger, the staleness sweep,
//! the attack-surface map, and the findings ledger. No model calls — every
//! row carries the mechanical evidence that produced it.

mod domain;
mod fold;
mod gather;
mod saved;
#[cfg(test)]
mod tests;

pub use domain::{ReasonTag, ScanRecommendation};
pub use fold::{recommend, RecommenderInputs};
pub(crate) use gather::scope_paths;
pub use gather::{recommend_scans_for_target, recommend_scans_from_history};
pub use saved::load_saved_scan_recommendations;
