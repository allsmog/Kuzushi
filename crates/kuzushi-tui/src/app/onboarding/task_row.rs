use super::task_id::PlanningTaskId;
use kuzushi_core::workspace::ArtifactState as CoreArtifactState;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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
    Blocked,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanningOperation {
    pub(crate) prepared_input: Value,
    pub(crate) operation_fingerprint: String,
}

impl PlanningTaskRow {
    pub fn for_task(task: PlanningTaskId, target: &Path) -> Self {
        let required_cli = task.required_cli();
        let cli_blocked = required_cli.is_some_and(|cli| !cli_is_on_path(cli));
        let blocker = task_workspace_blocker(task, target);
        let cli_available = !cli_blocked && blocker.is_none();
        let (artifact_path, artifact_state, artifact_modified) = match task.artifact_path(target) {
            Some(path) => {
                let state = cpg_aware_artifact_state(task, target, &path);
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
pub(crate) fn overlay_last_attempts(
    rows: &mut [PlanningTaskRow],
    target: &Path,
    operations: &BTreeMap<PlanningTaskId, PlanningOperation>,
) {
    let runs = recent_terminal_runs(target);
    for row in rows.iter_mut() {
        let Some(operation) = operations.get(&row.id) else {
            row.last_attempt = None;
            continue;
        };
        row.last_attempt = runs
            .iter()
            .find(|run| run_matches_operation(target, row, operation, run))
            .and_then(|run| last_attempt(target, row, operation, &run.status, &run.run_id));
    }
}

pub(crate) fn tasks_with_recent_attempts(
    rows: &[PlanningTaskRow],
    target: &Path,
) -> BTreeSet<PlanningTaskId> {
    let runs = recent_terminal_runs(target);
    rows.iter()
        .filter(|row| {
            runs.iter().any(|run| {
                run.tool == row.tool_name
                    && same_target(target, &run.target)
                    && same_target_revision(target, run)
            })
        })
        .map(|row| row.id)
        .collect()
}

#[derive(Debug)]
struct TerminalRun {
    run_id: String,
    status: String,
    tool: String,
    target: String,
    revision: Option<String>,
    dirty: bool,
}

fn recent_terminal_runs(target: &Path) -> Vec<TerminalRun> {
    let mut runs = Vec::new();
    let Ok(entries) =
        kuzushi_core::list_recent_run_summary_entries(target, LAST_ATTEMPT_SCAN_LIMIT)
    else {
        return runs;
    };
    for entry in entries {
        let kuzushi_core::RunSummaryEntryState::Ready(summary) = entry.state else {
            continue;
        };
        let Some(tool) = summary.tool else {
            continue;
        };
        if terminal_run_status(&summary.status) {
            let (revision, dirty) = summary
                .target_git
                .map(|git| (Some(git.sha), git.dirty))
                .unwrap_or_default();
            runs.push(TerminalRun {
                run_id: entry.run_id,
                status: summary.status,
                tool,
                target: summary.target,
                revision,
                dirty,
            });
        }
    }
    runs
}

fn run_matches_operation(
    target: &Path,
    row: &PlanningTaskRow,
    operation: &PlanningOperation,
    run: &TerminalRun,
) -> bool {
    run.tool == row.tool_name
        && same_target(target, &run.target)
        && same_target_revision(target, run)
        && run_input(target, &run.run_id).as_ref() == Some(&operation.prepared_input)
        && run_operation_fingerprint(target, &run.run_id, row.tool_name)
            .is_none_or(|fingerprint| fingerprint == operation.operation_fingerprint)
}

fn same_target(target: &Path, recorded: &str) -> bool {
    let current = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    let recorded = Path::new(recorded)
        .canonicalize()
        .unwrap_or_else(|_| Path::new(recorded).to_path_buf());
    current == recorded
}

fn same_target_revision(target: &Path, run: &TerminalRun) -> bool {
    let current = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target);
    current.revision == run.revision && current.dirty == run.dirty
}

fn run_input(target: &Path, run_id: &str) -> Option<Value> {
    let kuzushi_core::RunArtifactRead::Ready { value, .. } =
        kuzushi_core::read_run_artifact_text(target, run_id, "input.json")
    else {
        return None;
    };
    serde_json::from_str(&value).ok()
}

fn run_operation_fingerprint(target: &Path, run_id: &str, tool: &str) -> Option<String> {
    let read = kuzushi_core::run_lifecycle::read_run_items(target, run_id)
        .ok()
        .flatten()?;
    read.items.into_iter().find_map(|item| match item.item {
        kuzushi_core::run_lifecycle::RunItemV1::ToolCallRequested {
            tool_name,
            operation_fingerprint,
            ..
        } if tool_name.as_str() == tool => Some(operation_fingerprint.as_str().to_string()),
        _ => None,
    })
}

fn terminal_run_status(status: &str) -> bool {
    matches!(
        status,
        "completed" | "blocked" | "failed" | "partial" | "interrupted" | "canceled"
    )
}

fn last_attempt(
    target: &Path,
    row: &PlanningTaskRow,
    operation: &PlanningOperation,
    status: &str,
    run_id: &str,
) -> Option<LastAttempt> {
    match status {
        "completed" => Some(LastAttempt::Completed),
        "blocked" => Some(LastAttempt::Blocked),
        "failed" | "partial" | "interrupted" => {
            Some(failed_attempt(target, row, operation, run_id))
        }
        _ => None,
    }
}

fn failed_attempt(
    target: &Path,
    row: &PlanningTaskRow,
    operation: &PlanningOperation,
    run_id: &str,
) -> LastAttempt {
    let continuation = kuzushi_core::modules::tool_continuation(row.tool_name);
    let coordinates = kuzushi_core::run_artifacts::checkpoint_coordinates_for_run(target, run_id)
        .filter(|coordinates| {
            operation
                .operation_fingerprint
                .strip_prefix("blake3:")
                .is_some_and(|fingerprint| fingerprint == coordinates.fingerprint)
        });
    let resumable = continuation.is_continuable() && coordinates.is_some();
    LastAttempt::Failed {
        resumable,
        resume_from: coordinates.and_then(|coordinates| coordinates.resume_from),
    }
}

/// The live threat model's real methodology + ledger version, so the picker
/// says "cached · stride v4" instead of guessing from the row that built it.
fn cached_row_detail(task: PlanningTaskId, target: &Path, state: ArtifactState) -> Option<String> {
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

/// The CPG-build row's cache truth is whole-graph artifacts for the current
/// shape version (`has_artifacts`), not a populated `.kuzushi/cpg-rs` dir: a
/// dir holding only scoped/ graphs, only stale-shape graphs, or a failed
/// build's debris is NOT a usable graph and every cpg_taint_paths call would
/// error, so it must read as not-Cached rather than a false "Cached".
fn cpg_aware_artifact_state(task: PlanningTaskId, target: &Path, path: &Path) -> ArtifactState {
    if task == PlanningTaskId::BuildCodePropertyGraph {
        return if kuzushi_core::cpg_has_artifacts(target) {
            ArtifactState::Cached
        } else {
            ArtifactState::Missing
        };
    }
    artifact_state(target, path)
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

    fn write_cpg_dir(target: &Path) -> PathBuf {
        let dir = target.join(".kuzushi").join("cpg-rs");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cpg_row_not_cached_with_only_scoped_or_stale_graphs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = write_cpg_dir(tmp.path());
        // Stale-shape flat graph plus a current-shape scoped graph: the dir is
        // populated (a bare is_dir()/read_dir would say "Cached"), but neither
        // is a usable whole-graph artifact for the current shape version.
        std::fs::write(dir.join("go.v1.cpg"), b"x").unwrap();
        let scoped = dir.join("scoped").join("svc");
        std::fs::create_dir_all(&scoped).unwrap();
        std::fs::write(
            scoped.join(format!("go.v{}.cpg", kuzushi_core::CPG_GRAPH_SHAPE_VERSION)),
            b"x",
        )
        .unwrap();

        let row = PlanningTaskRow::for_task(PlanningTaskId::BuildCodePropertyGraph, tmp.path());
        assert_eq!(row.artifact_state, ArtifactState::Missing);
    }

    #[test]
    fn cpg_row_cached_with_a_current_shape_whole_graph() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = write_cpg_dir(tmp.path());
        std::fs::write(
            dir.join(format!("go.v{}.cpg", kuzushi_core::CPG_GRAPH_SHAPE_VERSION)),
            b"x",
        )
        .unwrap();

        let row = PlanningTaskRow::for_task(PlanningTaskId::BuildCodePropertyGraph, tmp.path());
        assert_eq!(row.artifact_state, ArtifactState::Cached);
    }

    #[test]
    fn uaf_hunt_row_blocks_without_compile_commands_json() {
        let tmp = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::HuntUseAfterFree, tmp.path());
        assert!(!row.cli_available);
        assert!(row.cost_hint().contains("requires compile_commands.json"));
    }

    #[test]
    fn planning_history_skips_tools_without_a_terminal_attempt() {
        let target = tempfile::tempdir().unwrap();
        let rows = [PlanningTaskRow::for_task(
            PlanningTaskId::BuildCodeQlDatabase,
            target.path(),
        )];

        assert!(tasks_with_recent_attempts(&rows, target.path()).is_empty());
    }

    #[test]
    fn planning_history_selects_a_matching_terminal_attempt() {
        let target = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::ScanAgenticSast, target.path());
        record_terminal_run(
            target.path(),
            "tool-completed",
            row.tool_name,
            &serde_json::json!({}),
            "completed",
            100,
        );

        assert_eq!(
            tasks_with_recent_attempts(std::slice::from_ref(&row), target.path()),
            BTreeSet::from([row.id])
        );
    }

    #[test]
    fn newest_blocked_attempt_supersedes_an_older_completion() {
        let target = tempfile::tempdir().unwrap();
        let mut row = PlanningTaskRow::for_task(PlanningTaskId::ScanAgenticSast, target.path());
        record_terminal_run(
            target.path(),
            "tool-100-completed",
            row.tool_name,
            &serde_json::json!({}),
            "completed",
            100,
        );
        record_terminal_run(
            target.path(),
            "tool-200-blocked",
            row.tool_name,
            &serde_json::json!({}),
            "blocked",
            200,
        );

        let operation = PlanningOperation {
            prepared_input: serde_json::json!({}),
            operation_fingerprint:
                "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
        };
        let operations = BTreeMap::from([(row.id, operation)]);
        overlay_last_attempts(std::slice::from_mut(&mut row), target.path(), &operations);

        assert_eq!(row.last_attempt, Some(LastAttempt::Blocked));
    }

    #[test]
    fn newer_same_tool_with_different_input_does_not_hide_matching_operation() {
        let target = tempfile::tempdir().unwrap();
        let mut row = PlanningTaskRow::for_task(PlanningTaskId::ScanAgenticSast, target.path());
        record_terminal_run(
            target.path(),
            "tool-100-current",
            row.tool_name,
            &serde_json::json!({"maxFindings": 8}),
            "completed",
            100,
        );
        record_terminal_run(
            target.path(),
            "tool-200-other",
            row.tool_name,
            &serde_json::json!({"maxFindings": 99}),
            "failed",
            200,
        );
        let operation = planning_operation(serde_json::json!({"maxFindings": 8}));
        let task = row.id;

        overlay_last_attempts(
            std::slice::from_mut(&mut row),
            target.path(),
            &BTreeMap::from([(task, operation)]),
        );

        assert_eq!(row.last_attempt, Some(LastAttempt::Completed));
    }

    #[test]
    fn newer_same_input_from_another_revision_is_ignored() {
        let target = tempfile::tempdir().unwrap();
        let mut row = PlanningTaskRow::for_task(PlanningTaskId::ScanAgenticSast, target.path());
        record_terminal_run(
            target.path(),
            "tool-100-current",
            row.tool_name,
            &serde_json::json!({}),
            "completed",
            100,
        );
        let mut other = kuzushi_core::RunSummary::running(
            "tool-200-other-revision",
            "tool",
            Some(row.tool_name.to_string()),
            target.path().display().to_string(),
        )
        .with_target_git(Some(kuzushi_core::RunTargetGitMetadata {
            sha: "different-revision".to_string(),
            branch: None,
            dirty: false,
        }));
        other.started_at_unix = 200;
        kuzushi_core::write_run_summary(target.path(), &other).unwrap();
        record_terminal_run(
            target.path(),
            "tool-200-other-revision",
            row.tool_name,
            &serde_json::json!({}),
            "failed",
            200,
        );
        let task = row.id;

        overlay_last_attempts(
            std::slice::from_mut(&mut row),
            target.path(),
            &BTreeMap::from([(task, planning_operation(serde_json::json!({})))]),
        );

        assert_eq!(row.last_attempt, Some(LastAttempt::Completed));
    }

    #[test]
    fn partial_operation_without_matching_checkpoint_retries_from_start() {
        let target = tempfile::tempdir().unwrap();
        let mut row = PlanningTaskRow::for_task(PlanningTaskId::BuildThreatModel, target.path());
        record_terminal_run(
            target.path(),
            "tool-partial",
            row.tool_name,
            &serde_json::json!({}),
            "partial",
            100,
        );
        let task = row.id;

        overlay_last_attempts(
            std::slice::from_mut(&mut row),
            target.path(),
            &BTreeMap::from([(task, planning_operation(serde_json::json!({})))]),
        );

        assert_eq!(
            row.last_attempt,
            Some(LastAttempt::Failed {
                resumable: false,
                resume_from: None,
            })
        );
    }

    fn planning_operation(prepared_input: Value) -> PlanningOperation {
        PlanningOperation {
            prepared_input,
            operation_fingerprint:
                "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
        }
    }

    fn record_terminal_run(
        target: &Path,
        run_id: &str,
        tool: &str,
        input: &Value,
        status: &str,
        started_at: u64,
    ) {
        let record = kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "tool", tool);
        kuzushi_core::run_artifacts::record_tool_run_started(record, input);
        let mut summary = kuzushi_core::load_run_summary(target, run_id).unwrap();
        summary.status = status.to_string();
        summary.started_at_unix = started_at;
        summary.completed_at_unix = Some(started_at);
        kuzushi_core::write_run_summary(target, &summary).unwrap();
    }
}
