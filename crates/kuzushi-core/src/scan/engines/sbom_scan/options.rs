use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_SBOM_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_SBOM_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SBOM_TOTAL_BYTES: usize = 512 * 1024 * 1024;

/// Captured input bytes are retained for one inventory and reused by its parsers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomScanOptions {
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for SbomScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_SBOM_FILE_BYTES,
            max_total_bytes: DEFAULT_SBOM_TOTAL_BYTES,
        }
    }
}

impl SbomScanOptions {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        let options: Self = serde_json::from_value(json!({
            "maxFileBytes":input.get("maxFileBytes").cloned().unwrap_or(json!(MAX_SBOM_FILE_BYTES)),
            "maxTotalBytes":input.get("maxTotalBytes").cloned().unwrap_or(json!(DEFAULT_SBOM_TOTAL_BYTES)),
        }))?;
        options.validate()?;
        Ok(options)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=MAX_SBOM_FILE_BYTES).contains(&self.max_file_bytes),
            "sbom-scan maxFileBytes must be between 1 and {MAX_SBOM_FILE_BYTES}"
        );
        anyhow::ensure!(
            (1..=MAX_SBOM_TOTAL_BYTES).contains(&self.max_total_bytes),
            "sbom-scan maxTotalBytes must be between 1 and {MAX_SBOM_TOTAL_BYTES}"
        );
        Ok(())
    }
}
