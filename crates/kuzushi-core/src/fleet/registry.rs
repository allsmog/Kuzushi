use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const FLEET_TARGETS_FILE: &str = "targets.toml";

/// One registered scan target. The registry replaces the bare MRU list as
/// the fleet's source of target identity; `target-history.json` stays for
/// picker recency only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetTarget {
    pub id: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetsFile {
    #[serde(default, rename = "target")]
    targets: Vec<FleetTarget>,
}

/// `~/.kuzushi/v3/fleet/` for the current operator.
pub fn default_fleet_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not resolve home directory")?;
    Ok(crate::workspace::workspace_state_dir(home).join(super::FLEET_DIR))
}

pub fn load_fleet_targets(fleet_dir: &Path) -> Result<Vec<FleetTarget>> {
    let path = fleet_dir.join(FLEET_TARGETS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let file: TargetsFile = toml::from_str(&body)
        .with_context(|| format!("Malformed fleet registry {}", path.display()))?;
    Ok(file.targets)
}

/// Idempotent by id: re-registering an id replaces its entry.
pub fn register_fleet_target(fleet_dir: &Path, target: FleetTarget) -> Result<Vec<FleetTarget>> {
    anyhow::ensure!(!target.id.trim().is_empty(), "fleet target id cannot be blank");
    anyhow::ensure!(
        target.path.is_absolute(),
        "fleet target path must be absolute: {}",
        target.path.display()
    );
    let mut targets = load_fleet_targets(fleet_dir)?;
    targets.retain(|existing| existing.id != target.id);
    targets.push(target);
    targets.sort_by(|a, b| a.id.cmp(&b.id));
    save_fleet_targets(fleet_dir, &targets)?;
    Ok(targets)
}

fn save_fleet_targets(fleet_dir: &Path, targets: &[FleetTarget]) -> Result<()> {
    std::fs::create_dir_all(fleet_dir)
        .with_context(|| format!("Could not create {}", fleet_dir.display()))?;
    let body = toml::to_string_pretty(&TargetsFile {
        targets: targets.to_vec(),
    })
    .context("Could not serialize fleet registry")?;
    let path = fleet_dir.join(FLEET_TARGETS_FILE);
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))
}
