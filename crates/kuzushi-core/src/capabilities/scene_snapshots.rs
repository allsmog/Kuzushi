//! Per-repo persistence for the two security-viz snapshots that don't already
//! have a durable home: the headline taint flow (the `/scene` attack-path page,
//! produced by `taint-iris:hunt` as `data.flows[]`) and the exploit chains (the
//! exploit-chain page, produced by `exploit-chain:scan` as `data.chains[]`).
//!
//! Findings (the heatmap + 3D attack-surface pages) already persist in the
//! workspace findings store, and the threat model (the DFD page) persists via
//! [`crate::capabilities::persistent_threat_model_path`]. These two were the
//! only generated visualizations that vanished on restart; saving them under the
//! same `.kuzushi` state root keeps every page available for a repo across
//! sessions. The payload is the raw structured JSON the tools emit, reloaded by
//! the same parsers that handle the live tool result, so there is no second
//! schema to keep in sync.

use crate::workspace::{
    read_optional_workspace_text, workspace_state_root, write_workspace_state_file,
    KUZUSHI_STATE_DIR,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

const TAINT_FLOW_FILE: &str = "scene-taint-flow.json";
const EXPLOIT_CHAINS_FILE: &str = "scene-exploit-chains.json";
const MAX_SCENE_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

/// `<root>/.kuzushi/scene-taint-flow.json` — the persisted `{ "flows": [...] }`.
pub fn persistent_taint_flow_path(root: &Path) -> PathBuf {
    workspace_state_root(root).join(TAINT_FLOW_FILE)
}

/// `<root>/.kuzushi/scene-exploit-chains.json` — the persisted `{ "chains": [...] }`.
pub fn persistent_exploit_chains_path(root: &Path) -> PathBuf {
    workspace_state_root(root).join(EXPLOIT_CHAINS_FILE)
}

pub fn save_persistent_taint_flow(root: &Path, payload: &Value) -> Result<()> {
    write_scene_snapshot(root, TAINT_FLOW_FILE, payload)
}

pub fn load_persistent_taint_flow(root: &Path) -> Option<Value> {
    try_load_persistent_taint_flow(root).ok().flatten()
}

pub fn try_load_persistent_taint_flow(root: &Path) -> Result<Option<Value>> {
    read_scene_snapshot(root, &persistent_taint_flow_path(root))
}

pub fn save_persistent_exploit_chains(root: &Path, payload: &Value) -> Result<()> {
    write_scene_snapshot(root, EXPLOIT_CHAINS_FILE, payload)
}

pub fn load_persistent_exploit_chains(root: &Path) -> Option<Value> {
    try_load_persistent_exploit_chains(root).ok().flatten()
}

pub fn try_load_persistent_exploit_chains(root: &Path) -> Result<Option<Value>> {
    read_scene_snapshot(root, &persistent_exploit_chains_path(root))
}

fn write_scene_snapshot(root: &Path, file_name: &str, payload: &Value) -> Result<()> {
    let body = format!("{}\n", serde_json::to_string_pretty(payload)?);
    write_workspace_state_file(
        root,
        Path::new(KUZUSHI_STATE_DIR).join(file_name),
        body.as_bytes(),
    )?;
    Ok(())
}

fn read_scene_snapshot(root: &Path, path: &Path) -> Result<Option<Value>> {
    let Some(raw) = read_optional_workspace_text(root, path, MAX_SCENE_SNAPSHOT_BYTES)? else {
        return Ok(None);
    };
    serde_json::from_str(&raw)
        .map(Some)
        .with_context(|| format!("Could not parse scene snapshot {}", path.display()))
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

    #[cfg(unix)]
    #[test]
    fn scene_snapshot_writer_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let mut outside = tempfile::NamedTempFile::new().expect("outside");
        std::io::Write::write_all(&mut outside, b"outside").expect("seed outside");
        std::fs::create_dir_all(workspace_state_root(workspace.path())).expect("state dir");
        symlink(outside.path(), persistent_taint_flow_path(workspace.path()))
            .expect("symlink artifact");

        let error = save_persistent_taint_flow(workspace.path(), &json!({ "flows": [] }))
            .expect_err("symlink must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "outside");
    }

    #[cfg(unix)]
    #[test]
    fn fallible_scene_reader_rejects_an_outside_symlink_without_disclosing_content() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let outside = tempfile::NamedTempFile::new().expect("outside");
        std::fs::write(outside.path(), "OUTSIDE_SCENE_TOKEN").unwrap();
        std::fs::create_dir_all(workspace_state_root(workspace.path())).unwrap();
        symlink(outside.path(), persistent_taint_flow_path(workspace.path())).unwrap();

        let error = try_load_persistent_taint_flow(workspace.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("symlink"), "{error}");
        assert!(!error.contains("OUTSIDE_SCENE_TOKEN"));
    }
}
