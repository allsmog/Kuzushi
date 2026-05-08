/// P²-algorithm streaming quantile estimator. Maintains five marker
/// heights/positions and updates them as new samples arrive — O(1)
/// memory and O(1) update cost, no full sort needed.
///
/// Reference: Jain & Chlamtac, "The P² Algorithm for Dynamic
/// Calculation of Quantiles and Histograms Without Storing
/// Observations", CACM 28(10), 1985.

/// Score returned by the classifier — `[0.0, 1.0]` where 1.0 means
/// "almost certainly a real vulnerability".
use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::findings::{Finding, TriageOutcome, TriageVerdict};
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use anyhow::{Context, Result};
pub(crate) use classifier_gate_model::*;
pub(crate) use quantile_estimator::*;
pub(crate) use render_prompt::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
mod classifier_config;
mod classifier_gate_model;
mod likely_vuln_classifier;
mod marker_adjustment;
mod quantile_estimator;
mod quantile_estimator_update;
mod render_prompt;
#[cfg(test)]
mod tests;

pub use classifier_config::ClassifierConfig;
pub use classifier_config::Score;
pub use classifier_gate_model::LikelyVulnClassifier;
pub use quantile_estimator::QuantileEstimator;
pub use quantile_estimator::DEFAULT_COLD_START_FLOOR;
pub use quantile_estimator::DEFAULT_COLD_START_MIN_COUNT;
pub use quantile_estimator::DEFAULT_TARGET_PERCENTILE;
