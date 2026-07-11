use super::task_id::PlanningTaskId;
use kuzushi_core::workspace::ArtifactState as CoreArtifactState;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Per-row state shown in the planning picker. Built once at picker open
/// and refreshed when artifacts change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningTaskRow {
    pub id: PlanningTaskId,
    pub label: &'static str,
    pub tool_name: &'static str,
    pub artifact_path: PathBuf,
    pub artifact_state: ArtifactState,
    /// When the cached artifact was last written, so the picker can tell a
    /// returning operator when prior work happened. `None` for missing/action
    /// rows (nothing on disk to date).
    pub artifact_modified: Option<SystemTime>,
    pub model_backed: bool,
    pub required_cli: Option<&'static str>,
    pub cli_available: bool,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Cached,
    Invalid,
    Missing,
    /// The task is a re-runnable action (Hunt/Confirm/Fix scan, triage, patch)
    /// rather than an artifact build — there is nothing to cache or reuse.
    Action,
}

impl PlanningTaskRow {
    pub fn for_task(task: PlanningTaskId, target: &Path) -> Self {
        let required_cli = task.required_cli();
        let cli_blocked = required_cli.is_some_and(|cli| !cli_is_on_path(cli));
        let blocker = task_workspace_blocker(task, target);
        let cli_available = !cli_blocked && blocker.is_none();
        let (artifact_path, artifact_state, artifact_modified) = match task.artifact_relative_path()
        {
            Some(rel) => {
                let path = target.join(rel);
                let state = artifact_state(target, &path);
                let modified = artifact_modified(target, &path, state);
                (path, state, modified)
            }
            // Action tasks have no cached artifact; the path is a harmless
            // placeholder under the workspace state dir.
            None => (target.join(".kuzushi"), ArtifactState::Action, None),
        };
        Self {
            id: task,
            label: task.label(),
            tool_name: task.tool_name(),
            artifact_path,
            artifact_state,
            artifact_modified,
            model_backed: task.is_model_backed(),
            required_cli,
            cli_available,
            blocker,
        }
    }

    #[cfg(test)]
    /// Whether this row should be pre-checked when the picker first opens.
    /// An artifact-building row is pre-checked when its artifact is missing or
    /// invalid AND its required CLI is available. Action rows are opt-in here
    /// (the recommender supplies their preselection in the phase walker).
    pub fn pre_checked(&self) -> bool {
        if matches!(self.artifact_state, ArtifactState::Action) {
            return false;
        }
        self.cli_available
            && !matches!(self.artifact_state, ArtifactState::Cached)
            && !forced_off_by_default(self.id)
    }

    #[cfg(test)]
    /// One-line hint shown next to the row (cost + missing dep info). When the
    /// required CLI is absent the row can't run at all, so the blocker IS the
    /// hint — prefixing it with cost info only pushed the actionable part past
    /// the column budget where it got truncated.
    pub fn cost_hint(&self) -> String {
        if self.id.is_inline_action() {
            return "local UI action".to_string();
        }
        let base = if self.model_backed {
            "model-backed"
        } else {
            "no model cost"
        };
        if let Some(blocker) = &self.blocker {
            return blocker.clone();
        }
        match self.required_cli {
            Some(cli) if !self.cli_available => format!("requires {cli} — not on PATH"),
            Some(cli) => format!("{base} (requires {cli})"),
            None => base.to_string(),
        }
    }
}

#[cfg(test)]
/// PASTA is opt-in even when its artifact is missing — STRIDE is the
/// default methodology and we don't want to spend two LLM passes by
/// default.
fn forced_off_by_default(task: PlanningTaskId) -> bool {
    matches!(task, PlanningTaskId::BuildPastaThreatModel)
}

fn task_workspace_blocker(task: PlanningTaskId, target: &Path) -> Option<String> {
    if task == PlanningTaskId::HuntUseAfterFree
        && !super::recommend::has_compile_commands_json(target)
    {
        return Some(
            "requires compile_commands.json under target or build/ for clangd".to_string(),
        );
    }
    None
}

/// Last-modified time of an artifact, when it exists on disk. Used only for
/// the "prior work found ~N ago" orientation line — absence is not an error.
pub fn artifact_modified(target: &Path, path: &Path, state: ArtifactState) -> Option<SystemTime> {
    if state != ArtifactState::Cached {
        return None;
    }
    kuzushi_core::workspace::artifact_modified_within(target, path)
        .ok()
        .flatten()
}

pub fn artifact_state(target: &Path, path: &Path) -> ArtifactState {
    match kuzushi_core::workspace::artifact_state_within(target, path) {
        CoreArtifactState::Cached => ArtifactState::Cached,
        CoreArtifactState::Invalid => ArtifactState::Invalid,
        CoreArtifactState::Missing => ArtifactState::Missing,
    }
}

pub fn cli_is_on_path(name: &str) -> bool {
    if let Some(env_var) = cli_env_override(name) {
        if let Some(value) = std::env::var_os(env_var) {
            if std::path::Path::new(&value).is_file() {
                return true;
            }
        }
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
}

fn cli_env_override(name: &str) -> Option<&'static str> {
    match name {
        "joern-parse" => Some("KUZUSHI_JOERN_BIN"),
        "codeql" => Some("KUZUSHI_CODEQL_BIN"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_artifact_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            artifact_state(tmp.path(), &tmp.path().join("nope.json")),
            ArtifactState::Missing
        );
    }

    #[test]
    fn empty_directory_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("empty");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(artifact_state(tmp.path(), &dir), ArtifactState::Missing);
    }

    #[test]
    fn populated_directory_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("populated");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "x").unwrap();
        assert_eq!(artifact_state(tmp.path(), &dir), ArtifactState::Cached);
    }

    #[test]
    fn valid_json_file_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{}").unwrap();
        assert_eq!(artifact_state(tmp.path(), &path), ArtifactState::Cached);
    }

    #[test]
    fn malformed_json_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.json");
        std::fs::write(&path, "{not-json").unwrap();
        assert_eq!(artifact_state(tmp.path(), &path), ArtifactState::Invalid);
    }

    #[cfg(unix)]
    #[test]
    fn planning_artifact_probe_rejects_symlinked_state_parent() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("context-snapshot.json"), "{}").unwrap();
        symlink(outside.path(), target.path().join(".kuzushi")).unwrap();
        let path = target.path().join(".kuzushi/context-snapshot.json");

        assert_eq!(artifact_state(target.path(), &path), ArtifactState::Invalid);
        assert_eq!(
            artifact_modified(target.path(), &path, ArtifactState::Invalid),
            None
        );
    }

    #[test]
    fn pasta_defaults_off_even_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::BuildPastaThreatModel, tmp.path());
        assert!(!row.pre_checked());
    }

    #[test]
    fn uaf_hunt_row_blocks_without_compile_commands_json() {
        let tmp = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::HuntUseAfterFree, tmp.path());
        assert!(!row.cli_available);
        assert!(row.cost_hint().contains("requires compile_commands.json"));
    }
}
