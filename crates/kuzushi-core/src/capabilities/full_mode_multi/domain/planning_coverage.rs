use crate::workspace::{InventoryInspection, InventoryPathClassification};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanningCoverage {
    pub enumeration: String,
    pub inventory: Option<InventoryInspection>,
    pub inventory_limitation: Option<String>,
    pub enumeration_incomplete: bool,
    pub excluded_paths: Vec<InventoryPathClassification>,
    pub omitted_sources: Vec<InventoryPathClassification>,
    pub selected_source_bytes: usize,
    pub planning_read_bytes: usize,
    pub max_source_bytes: usize,
    pub max_source_files: usize,
    pub canceled: bool,
}

impl PlanningCoverage {
    pub fn is_partial(&self) -> bool {
        self.enumeration_incomplete || self.canceled || !self.omitted_sources.is_empty()
    }
}
