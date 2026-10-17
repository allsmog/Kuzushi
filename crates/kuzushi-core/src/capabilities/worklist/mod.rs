//! Risk-ranked file worklist: a deterministic fold over existing rankers
//! (attack surface, scan-coverage recommendations, opt-in systems-hunt). No
//! model calls, no implicit graph builds — every row carries the raw evidence
//! of each contributing ranker plus an honest per-contributor state.

#[cfg(test)]
mod deep_tests;
mod domain;
mod fold;
mod gather;
#[cfg(test)]
mod tests;

pub use domain::{
    Citation, Contributor, ContributorState, UnrankedFile, Worklist, WorklistRow, WEIGHTS,
};
pub use fold::{rank, RecommendationsStatus, WorklistInputs};
pub(crate) use gather::rank_worklist_observed;
pub use gather::{rank_worklist_for_target, WorklistOptions};
