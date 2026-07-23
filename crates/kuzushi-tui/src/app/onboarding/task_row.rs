use super::task_id::PlanningTaskId;
use kuzushi_core::workspace::ArtifactState as CoreArtifactState;
use std::collections::BTreeMap;
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
    /// Honest cache identity for the merged threat-model row: the live
    /// artifact's real methodology plus its ledger version ("stride v4").
    /// None for other rows or when nothing is cached.
    pub cached_detail: Option<String>,
    /// Most recent terminal run outcome for this task's tool, overlaid from
    /// the run ledger by `overlay_last_attempts`. Drives honest
    /// preselection: failed-but-resumable ⇒ pre-checked continue; work
    /// completed this pass is never silently re-checked.
    pub last_attempt: Option<LastAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastAttempt {
    Completed,
    Failed {
        /// The tool declares continuation and left resumable state behind —
        /// re-running the same task resumes instead of restarting.
        resumable: bool,
        resume_from: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Cached,
    Invalid,
    Missing,
    /// The task is a re-runnable action (Scan/Review/Prove/Fix work)
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
        let cached_detail = cached_row_detail(task, target, artifact_state);
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
            cached_detail,
            last_attempt: None,
        }
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

const LAST_ATTEMPT_SCAN_LIMIT: usize = 50;

/// Overlay each row's most recent terminal run outcome from the run ledger
/// (bounded newest-first scan). Called at picker build and refresh so
/// preselection reflects what actually happened, not a static table.
pub(crate) fn overlay_last_attempts(rows: &mut [PlanningTaskRow], target: &Path) {
    let newest = newest_terminal_runs(target);
    for row in rows.iter_mut() {
        row.last_attempt = newest
            .get(row.tool_name)
            .and_then(|(status, run_id)| last_attempt(target, row, status, run_id));
    }
}

/// Newest terminal (status, run id) per tool from the run ledger.
fn newest_terminal_runs(target: &Path) -> BTreeMap<String, (String, String)> {
    let mut newest = BTreeMap::new();
    let Ok(entries) =
        kuzushi_core::list_recent_run_summary_entries(target, LAST_ATTEMPT_SCAN_LIMIT)
    else {
        return newest;
    };
    for entry in entries {
        let kuzushi_core::RunSummaryEntryState::Ready(summary) = entry.state else {
            continue;
        };
        let Some(tool) = summary.tool else {
            continue;
        };
        if terminal_run_status(&summary.status) {
            newest.entry(tool).or_insert((summary.status, entry.run_id));
        }
    }
    newest
}

fn terminal_run_status(status: &str) -> bool {
    matches!(
        status,
        "completed" | "failed" | "partial" | "interrupted" | "canceled"
    )
}

fn last_attempt(
    target: &Path,
    row: &PlanningTaskRow,
    status: &str,
    run_id: &str,
) -> Option<LastAttempt> {
    match status {
        "completed" => Some(LastAttempt::Completed),
        "failed" | "partial" | "interrupted" => Some(failed_attempt(target, row, run_id)),
        _ => None,
    }
}

fn failed_attempt(target: &Path, row: &PlanningTaskRow, run_id: &str) -> LastAttempt {
    let continuation = kuzushi_core::modules::tool_continuation(row.tool_name);
    let coordinates =
        kuzushi_core::run_artifacts::checkpoint_coordinates_for_run(target, run_id);
    let resumable = continuation.is_continuable()
        && (coordinates.is_some()
            || matches!(
                continuation,
                kuzushi_core::modules::ContinuationSupport::Loop
            ));
    LastAttempt::Failed {
        resumable,
        resume_from: coordinates.and_then(|coordinates| coordinates.resume_from),
    }
}

/// The live threat model's real methodology + ledger version, so the picker
/// says "cached · stride v4" instead of guessing from the row that built it.
fn cached_row_detail(
    task: PlanningTaskId,
    target: &Path,
    state: ArtifactState,
) -> Option<String> {
    if task != PlanningTaskId::BuildThreatModel || state != ArtifactState::Cached {
        return None;
    }
    let document = kuzushi_core::load_persistent_threat_model(target)?;
    let methodology = document
        .get("methodology")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let version = kuzushi_core::list_threat_model_versions(target, 1)
        .ok()
        .and_then(|versions| versions.first().map(|record| record.id));
    Some(match version {
        Some(version) => format!("{methodology} v{version}"),
        None => methodology,
    })
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
    fn merged_threat_model_row_probes_the_live_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::BuildThreatModel, tmp.path());
        assert!(row.artifact_path.ends_with(".kuzushi/threat-model.json"));
        assert_eq!(row.artifact_state, ArtifactState::Missing);
    }

    #[test]
    fn uaf_hunt_row_blocks_without_compile_commands_json() {
        let tmp = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::HuntUseAfterFree, tmp.path());
        assert!(!row.cli_available);
        assert!(row.cost_hint().contains("requires compile_commands.json"));
    }
}
