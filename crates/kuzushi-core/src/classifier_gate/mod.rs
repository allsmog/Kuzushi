/// P²-algorithm streaming quantile estimator. Maintains five marker
/// heights/positions and updates them as new samples arrive — O(1)
/// memory and O(1) update cost, no full sort needed.
///
/// Reference: Jain & Chlamtac, "The P² Algorithm for Dynamic
/// Calculation of Quantiles and Histograms Without Storing
/// Observations", CACM 28(10), 1985.

/// Score returned by the classifier — `[0.0, 1.0]` where 1.0 means
/// "almost certainly a real vulnerability".
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_5;
mod new;
#[cfg(test)]
mod tests;

pub use items_1::QuantileEstimator;
pub use items_1::DEFAULT_COLD_START_FLOOR;
pub use items_1::DEFAULT_COLD_START_MIN_COUNT;
pub use items_1::DEFAULT_TARGET_PERCENTILE;
pub use items_2::ClassifierConfig;
pub use items_2::Score;
pub use items_3::LikelyVulnClassifier;
