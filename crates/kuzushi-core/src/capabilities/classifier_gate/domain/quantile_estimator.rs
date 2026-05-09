use serde::{Deserialize, Serialize};

pub const DEFAULT_TARGET_PERCENTILE: f32 = 0.80;

pub const DEFAULT_COLD_START_FLOOR: f32 = 0.6;

pub const DEFAULT_COLD_START_MIN_COUNT: usize = 50;

pub(crate) const STATE_KEY: &str = "classifier.likely_vuln.quantile";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantileEstimator {
    /// Target percentile, e.g. 0.80.
    pub p: f32,
    /// Heights of the five markers q[0..5].
    pub(crate) q: [f64; 5],
    /// Actual positions n[0..5] (1-indexed).
    pub(crate) n: [f64; 5],
    /// Desired positions np[0..5].
    pub(crate) np: [f64; 5],
    /// Increments dn[0..5].
    pub(crate) dn: [f64; 5],
    /// Number of samples seen.
    pub count: usize,
}
