use super::{DEFAULT_COLD_START_FLOOR, DEFAULT_COLD_START_MIN_COUNT, DEFAULT_TARGET_PERCENTILE};

pub type Score = f32;

#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub target_percentile: f32,
    pub cold_start_floor: f32,
    pub cold_start_min_count: usize,
    /// Path to the SQLite DB used to persist the quantile across
    /// invocations. `None` = in-memory only (tests / dry runs).
    pub state_db: Option<std::path::PathBuf>,
}

impl ClassifierConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.target_percentile.is_finite()
                && self.target_percentile > 0.0
                && self.target_percentile < 1.0,
            "targetPercentile must be finite and strictly between 0 and 1"
        );
        anyhow::ensure!(
            self.cold_start_floor.is_finite() && (0.0..=1.0).contains(&self.cold_start_floor),
            "Classifier cold-start floor must be finite and within 0 to 1"
        );
        Ok(())
    }
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            target_percentile: DEFAULT_TARGET_PERCENTILE,
            cold_start_floor: DEFAULT_COLD_START_FLOOR,
            cold_start_min_count: DEFAULT_COLD_START_MIN_COUNT,
            state_db: None,
        }
    }
}
