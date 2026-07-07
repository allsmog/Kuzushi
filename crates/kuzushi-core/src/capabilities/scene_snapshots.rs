//! Per-repo persistence for the two security-viz snapshots that don't already
//! have a durable home: the headline taint flow (the `/scene` attack-path page,
//! produced by `taint-iris:hunt` as `data.flows[]`) and the exploit chains (the
//! exploit-chain page, produced by `exploit-chain:scan` as `data.chains[]`).
//!
//! Findings (the heatmap + 3D attack-surface pages) already persist in the
//! workspace findings store, and the threat model (the DFD page) persists via
//! [`crate::capabilities::persistent_threat_model_path`]. These two were the
//! only generated visualizations that vanished on restart; saving them under the
//! same `.kuzushi/v3` state root keeps every page available for a repo across
//! sessions. The payload is the raw structured JSON the tools emit, reloaded by
//! the same parsers that handle the live tool result, so there is no second
//! schema to keep in sync.

use crate::workspace::workspace_state_root;
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const TAINT_FLOW_FILE: &str = "scene-taint-flow.json";
const EXPLOIT_CHAINS_FILE: &str = "scene-exploit-chains.json";

/// `<root>/.kuzushi/v3/scene-taint-flow.json` — the persisted `{ "flows": [...] }`.
pub fn persistent_taint_flow_path(root: &Path) -> PathBuf {
    workspace_state_root(root).join(TAINT_FLOW_FILE)
}

/// `<root>/.kuzushi/v3/scene-exploit-chains.json` — the persisted `{ "chains": [...] }`.
pub fn persistent_exploit_chains_path(root: &Path) -> PathBuf {
    workspace_state_root(root).join(EXPLOIT_CHAINS_FILE)
}

pub fn save_persistent_taint_flow(root: &Path, payload: &Value) -> Result<()> {
    write_scene_snapshot(&persistent_taint_flow_path(root), payload)
}

pub fn load_persistent_taint_flow(root: &Path) -> Option<Value> {
    read_scene_snapshot(&persistent_taint_flow_path(root))
}

pub fn save_persistent_exploit_chains(root: &Path, payload: &Value) -> Result<()> {
    write_scene_snapshot(&persistent_exploit_chains_path(root), payload)
}

pub fn load_persistent_exploit_chains(root: &Path) -> Option<Value> {
    read_scene_snapshot(&persistent_exploit_chains_path(root))
}

fn write_scene_snapshot(path: &Path, payload: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(payload)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(())
}

fn read_scene_snapshot(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paths_use_workspace_state_root() {
        let root = Path::new("/repo");
        let state_root = workspace_state_root(root);
        assert_eq!(
            persistent_taint_flow_path(root),
            state_root.join(TAINT_FLOW_FILE)
        );
        assert_eq!(
            persistent_exploit_chains_path(root),
            state_root.join(EXPLOIT_CHAINS_FILE)
        );
    }

    #[test]
    fn taint_flow_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = json!({ "flows": [{ "cwe": "CWE-89", "severity": "critical" }] });
        assert!(load_persistent_taint_flow(dir.path()).is_none());
        save_persistent_taint_flow(dir.path(), &payload).expect("save");
        assert_eq!(load_persistent_taint_flow(dir.path()), Some(payload));
    }

    #[test]
    fn exploit_chains_round_trip_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = json!({ "chains": [{ "id": "c1", "name": "SQLi" }] });
        assert!(load_persistent_exploit_chains(dir.path()).is_none());
        save_persistent_exploit_chains(dir.path(), &payload).expect("save");
        assert_eq!(load_persistent_exploit_chains(dir.path()), Some(payload));
    }
}
