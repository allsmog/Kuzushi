use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const REMOTES_FILE: &str = "remotes.toml";

/// One remote scan box. Config is the only thing an operator edits here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBox {
    pub name: String,
    /// ssh destination, e.g. `user@devpod-3` or an ssh-config alias.
    pub ssh: String,
    /// Remote working directory holding the staged engine and queue.
    pub workdir: String,
    /// Concurrent queue slots on this box.
    #[serde(default = "default_slots")]
    pub slots: usize,
    /// tmux session prefix; sessions are `<prefix>-<slot>`.
    #[serde(default = "default_session_prefix")]
    pub session_prefix: String,
}

fn default_slots() -> usize {
    1
}

fn default_session_prefix() -> String {
    "kz-fleet".to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemotesFile {
    #[serde(default, rename = "remote")]
    remotes: Vec<RemoteBox>,
}

pub fn load_remotes(fleet_dir: &Path) -> Result<Vec<RemoteBox>> {
    let path = fleet_dir.join(REMOTES_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let file: RemotesFile = toml::from_str(&body)
        .with_context(|| format!("Malformed remotes config {}", path.display()))?;
    Ok(file.remotes)
}

pub fn find_remote<'boxes>(remotes: &'boxes [RemoteBox], name: &str) -> Result<&'boxes RemoteBox> {
    remotes
        .iter()
        .find(|remote| remote.name == name)
        .with_context(|| {
            format!(
                "unknown remote {name:?}; known: {}",
                remotes
                    .iter()
                    .map(|remote| remote.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

pub fn default_fleet_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".kuzushi/v3/fleet"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes_roundtrip_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(REMOTES_FILE),
            r#"
[[remote]]
name = "devpod-3"
ssh = "ubuntu@devpod-3"
workdir = "/home/ubuntu/kz-fleet"
"#,
        )
        .unwrap();

        let remotes = load_remotes(dir.path()).unwrap();

        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].slots, 1);
        assert_eq!(remotes[0].session_prefix, "kz-fleet");
        assert!(find_remote(&remotes, "devpod-3").is_ok());
        assert!(find_remote(&remotes, "nope").is_err());
    }

    #[test]
    fn missing_config_means_no_remotes_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_remotes(dir.path()).unwrap().is_empty());
    }
}
