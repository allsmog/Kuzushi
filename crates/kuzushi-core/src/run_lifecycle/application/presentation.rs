use super::{
    CallKind, ProjectionHealth, RunDeliveryHealth, RunDerivativeDeliveryHealth,
    RunDurabilityHealth, RunLifecycleHealth, RunProgressFidelity, RunProjection,
};
use crate::run_lifecycle::{
    ArtifactReference, DiagnosticLevel, FindingDeltaSummary, ModelUsage, OperatorChoice,
    OperatorDecisionValue, RunCallId, RunId, RunItemEnvelopeV1, RunItemId, RunItemStatus,
    RunItemV1, RunProjectionRead, RunProjectionSource, RunQuestionId, RunTaskId, SafeText,
    WorkflowContinuation,
};
use crate::runtime::RuntimeCostReport;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

mod call_details;
mod completion_quarantine;
mod display;
mod evidence;
mod hydration;
mod model;
mod ordering;
mod outcome;
mod payloads;
mod presenter;
mod timeline;
mod work;

pub use display::cost_label;
pub use hydration::RunPresentationHydrationV1;
pub use model::*;
pub use payloads::*;
pub use presenter::{
    present_projection, present_projection_with_hydration,
    present_projection_with_hydration_and_health, present_run,
};

#[cfg(test)]
#[path = "presentation/tests.rs"]
mod tests;
