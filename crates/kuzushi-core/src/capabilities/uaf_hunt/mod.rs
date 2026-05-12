pub(crate) mod adapters;
pub(crate) mod application;
pub mod domain;
pub(crate) mod persistence;

#[cfg(test)]
mod tests;

pub use adapters::{execute_uaf_hunt_tool, report_to_tool_json};
pub use application::run_uaf_hunt_report;
pub use domain::{
    default_alloc_free_pairs, AllocFreePair, UafHuntInput, UafHuntPersistedRun, UafHuntReport,
};
