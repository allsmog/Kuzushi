//! Typed, bounded, replayable lifecycle records for one Kuzushi run.

mod application;
mod domain;
mod persistence;

pub use application::*;
pub use domain::*;
pub use persistence::{
    load_run_projection, read_run_items, CommittedItemSubscriber, CommittedRange,
    CommittedRangeSubscriber, DerivativeRangeSubscriber, RunItemDeliveryFailureStage,
    RunItemDeliveryFault, RunItemDeliveryFaultSubscriber, RunItemRead, RunItemWriter,
    RunItemWriterFault, RunProjectionRead, RunProjectionSource,
};
pub(crate) use persistence::load_run_projection_unhydrated;

#[cfg(test)]
mod tests;
