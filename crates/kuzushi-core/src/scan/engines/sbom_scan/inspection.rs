use super::{SbomScanOptions, SbomScanReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomInputReceipt {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encoded_path_sha256: Option<String>,
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomInputInspection {
    pub limits: SbomScanOptions,
    pub reserved_source_bytes: u64,
    pub source_bytes_read: u64,
    pub captured_files: usize,
    pub captured_bytes: usize,
    pub inputs: Vec<SbomInputReceipt>,
    pub captured_input_sha256: String,
}

/// Adds resource evidence without changing the existing public report fields.
#[derive(Debug)]
pub struct InspectedSbomReport {
    pub report: SbomScanReport,
    pub inspection: SbomInputInspection,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SbomInspectionError {
    pub message: String,
    pub inspection: SbomInputInspection,
}
