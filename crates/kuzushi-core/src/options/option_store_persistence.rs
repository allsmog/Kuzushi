use super::ToolOptionStore;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

impl ToolOptionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Could not read option store {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("Could not parse option store {}", path.display()))
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Could not create option store directory {}",
                    parent.display()
                )
            })?;
        }
        let body =
            serde_json::to_string_pretty(self).context("Could not serialize option store")?;
        fs::write(path, body)
            .with_context(|| format!("Could not write option store {}", path.display()))
    }
}
