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
