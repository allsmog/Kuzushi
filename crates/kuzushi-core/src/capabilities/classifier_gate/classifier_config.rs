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
