//! Operator-owned report presentation choices, never export authorization.
use super::{read_optional_workspace_text, write_workspace_state_file, WorkspaceExportCompleteness, WorkspaceExportFormat};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_BYTES: usize = 32 * 1024;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportPreferences {
    pub schema_version: u8,
    pub target: PathBuf,
    pub format: WorkspaceExportFormat,
    pub completeness: WorkspaceExportCompleteness,
    pub destinations: BTreeMap<String, String>,
    pub provenance_details: bool,
}

impl ReportPreferences {
    pub fn validate(&self, target: &Path) -> Result<()> {
        anyhow::ensure!(self.schema_version == 1, "Unsupported saved report choices version");
        anyhow::ensure!(self.target == target, "Saved report choices belong to a different target");
        anyhow::ensure!(self.destinations.len() == 6, "Saved report choices must name all six formats");
        for (format, path) in &self.destinations {
            let parsed = WorkspaceExportFormat::from_input(format)?;
            anyhow::ensure!(parsed.as_str() == format, "Saved report format keys must be canonical");
            validate_destination(path)?;
        }
        Ok(())
    }
}

pub fn load_report_preferences(home: &Path, target: &Path) -> Result<Option<ReportPreferences>> {
    let target = std::fs::canonicalize(target).context("Could not resolve the report target")?;
    let path = preference_path(home, &target);
    let Some(text) = read_optional_workspace_text(home, &path, MAX_BYTES)? else { return Ok(None); };
    let preferences: ReportPreferences = serde_json::from_str(&text).context("Saved report choices are malformed")?;
    preferences.validate(&target)?;
    Ok(Some(preferences))
}

pub fn save_report_preferences(home: &Path, preferences: &ReportPreferences) -> Result<PathBuf> {
    let target = std::fs::canonicalize(&preferences.target).context("Could not resolve the report target")?;
    let mut normalized = preferences.clone();
    normalized.target = target.clone();
    normalized.validate(&target)?;
    let body = serde_json::to_vec_pretty(&normalized)?;
    anyhow::ensure!(body.len() <= MAX_BYTES, "Saved report choices exceed 32 KiB");
    let relative = preference_relative_path(&target);
    write_workspace_state_file(home, relative, &body)
}

fn preference_path(home: &Path, target: &Path) -> PathBuf {
    home.join(preference_relative_path(target))
}

fn preference_relative_path(target: &Path) -> PathBuf {
    let key = blake3::hash(target.as_os_str().as_encoded_bytes());
    Path::new(".kuzushi/v3/report-choices").join(format!("{key}.json"))
}

fn validate_destination(path: &str) -> Result<()> {
    anyhow::ensure!(!path.trim().is_empty() && path.len() <= MAX_PATH_BYTES,
        "Saved report destination must contain 1 to 4096 bytes");
    anyhow::ensure!(!path.chars().any(char::is_control), "Saved report destination contains control characters");
    Ok(())
}

#[cfg(test)]
mod tests;
