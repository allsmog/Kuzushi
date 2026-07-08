//! Per-workspace "YOUR TOOLS" shelf: operator favorites plus a most-recently-
//! used ring. Recents are recorded at the shared dispatch boundary so scan,
//! shell, and run all agree. Persisted to a sibling state file — never mixed
//! into the operator's `options.json`, since recents churn on every run.

use crate::fs_atomic::write_atomic;
use crate::workspace::{workspace_state_dir, WorkspaceTarget};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Sibling state file name under `<root>/.kuzushi/v3/`.
pub const WORKSPACE_TOOL_SHELF_FILE: &str = "tool-shelf.json";

/// Maximum number of recents retained (MRU ring).
pub const RECENTS_CAP: usize = 10;

/// One recorded recent-use entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentTool {
    pub tool: String,
    pub last_used_at: String,
    pub uses: u32,
}

/// Operator favorites + recents for one workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolShelf {
    #[serde(default)]
    favorites: Vec<String>,
    #[serde(default)]
    recents: Vec<RecentTool>,
}

impl ToolShelf {
    pub fn favorites(&self) -> &[String] {
        &self.favorites
    }

    pub fn recents(&self) -> &[RecentTool] {
        &self.recents
    }

    pub fn is_favorite(&self, tool: &str) -> bool {
        self.favorites.iter().any(|entry| entry == tool)
    }

    /// Toggle favorite membership, returning the resulting state (`true` when
    /// the tool is now a favorite).
    pub fn toggle_favorite(&mut self, tool: &str) -> bool {
        if let Some(index) = self.favorites.iter().position(|entry| entry == tool) {
            self.favorites.remove(index);
            false
        } else {
            self.favorites.push(tool.to_string());
            true
        }
    }

    /// Record a use of `tool` at timestamp `at`. Deduplicates by tool, keeps the
    /// most-recent first, bumps the use counter, and caps the ring.
    pub fn record_use(&mut self, tool: &str, at: &str) {
        let uses = match self.recents.iter().position(|entry| entry.tool == tool) {
            Some(index) => self.recents.remove(index).uses.saturating_add(1),
            None => 1,
        };
        self.recents.insert(
            0,
            RecentTool {
                tool: tool.to_string(),
                last_used_at: at.to_string(),
                uses,
            },
        );
        self.recents.truncate(RECENTS_CAP);
    }

    pub fn last_used(&self, tool: &str) -> Option<&str> {
        self.recents
            .iter()
            .find(|entry| entry.tool == tool)
            .map(|entry| entry.last_used_at.as_str())
    }

    /// Favorites first (in favorite order), then recents not already listed.
    pub fn shortlist(&self) -> Vec<&str> {
        let mut shortlist: Vec<&str> = self.favorites.iter().map(String::as_str).collect();
        for recent in &self.recents {
            if !shortlist.contains(&recent.tool.as_str()) {
                shortlist.push(recent.tool.as_str());
            }
        }
        shortlist
    }
}

/// Absolute path to the shelf file for a workspace root.
pub fn workspace_tool_shelf_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_TOOL_SHELF_FILE)
}

/// Load the shelf. A missing file is the empty default; a corrupt file is an
/// explicit error (no silent reset).
pub fn load_tool_shelf(target: &WorkspaceTarget) -> Result<ToolShelf> {
    let path = workspace_tool_shelf_path(target.root());
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents)
            .with_context(|| format!("Could not parse tool shelf at {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ToolShelf::default()),
        Err(error) => {
            Err(error).with_context(|| format!("Could not read tool shelf at {}", path.display()))
        }
    }
}

/// Persist the shelf atomically.
pub fn save_tool_shelf(target: &WorkspaceTarget, shelf: &ToolShelf) -> Result<()> {
    let path = workspace_tool_shelf_path(target.root());
    let contents = serde_json::to_string_pretty(shelf)
        .with_context(|| "Could not serialize tool shelf")?;
    write_atomic(&path, &contents)
}

/// Load-modify-save a recorded tool use. Used by the dispatch boundary.
pub fn record_tool_use(target: &WorkspaceTarget, tool: &str, at: &str) -> Result<()> {
    let mut shelf = load_tool_shelf(target)?;
    shelf.record_use(tool, at);
    save_tool_shelf(target, &shelf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_is_idempotent_pair() {
        let mut shelf = ToolShelf::default();
        assert!(shelf.toggle_favorite("semgrep:scan"));
        assert!(shelf.is_favorite("semgrep:scan"));
        assert!(!shelf.toggle_favorite("semgrep:scan"));
        assert!(!shelf.is_favorite("semgrep:scan"));
    }

    #[test]
    fn record_use_dedups_mru_and_bumps_uses() {
        let mut shelf = ToolShelf::default();
        shelf.record_use("a:x", "t1");
        shelf.record_use("b:y", "t2");
        shelf.record_use("a:x", "t3");
        assert_eq!(shelf.recents().len(), 2);
        assert_eq!(shelf.recents()[0].tool, "a:x");
        assert_eq!(shelf.recents()[0].uses, 2);
        assert_eq!(shelf.last_used("a:x"), Some("t3"));
    }

    #[test]
    fn recents_are_capped() {
        let mut shelf = ToolShelf::default();
        for i in 0..(RECENTS_CAP + 5) {
            shelf.record_use(&format!("m:{i}"), "t");
        }
        assert_eq!(shelf.recents().len(), RECENTS_CAP);
        // Most recent insert is at the front.
        assert_eq!(shelf.recents()[0].tool, format!("m:{}", RECENTS_CAP + 4));
    }

    #[test]
    fn shortlist_is_favorites_then_recents() {
        let mut shelf = ToolShelf::default();
        shelf.record_use("recent:one", "t");
        shelf.toggle_favorite("fav:one");
        shelf.record_use("fav:one", "t");
        let shortlist = shelf.shortlist();
        assert_eq!(shortlist, vec!["fav:one", "recent:one"]);
    }

    #[test]
    fn missing_file_is_empty_default() {
        let temp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(temp.path()).unwrap();
        assert_eq!(load_tool_shelf(&target).unwrap(), ToolShelf::default());
    }

    #[test]
    fn round_trips_through_disk() {
        let temp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(temp.path()).unwrap();
        target.ensure_state_dir().unwrap();
        let mut shelf = ToolShelf::default();
        shelf.toggle_favorite("semgrep:scan");
        shelf.record_use("triage:run", "2026-07-07T00:00:00Z");
        save_tool_shelf(&target, &shelf).unwrap();
        let loaded = load_tool_shelf(&target).unwrap();
        assert_eq!(loaded, shelf);
    }

    #[test]
    fn corrupt_file_is_explicit_error() {
        let temp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(temp.path()).unwrap();
        target.ensure_state_dir().unwrap();
        std::fs::write(workspace_tool_shelf_path(target.root()), "{not json").unwrap();
        assert!(load_tool_shelf(&target).is_err());
    }

    #[test]
    fn record_tool_use_persists() {
        let temp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(temp.path()).unwrap();
        target.ensure_state_dir().unwrap();
        record_tool_use(&target, "semgrep:scan", "t1").unwrap();
        let shelf = load_tool_shelf(&target).unwrap();
        assert_eq!(shelf.last_used("semgrep:scan"), Some("t1"));
    }
}
