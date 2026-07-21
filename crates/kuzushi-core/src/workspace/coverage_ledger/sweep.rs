use super::store::{BaselineRow, CoverageLedger};
use super::SWEEP_SKIP_MODE;
use crate::modules::WorkflowPhase;
use crate::run_artifacts::RunTargetGitMetadata;
use crate::workspace::{load_nested_project_scopes, ROOT_SCOPE_ID};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Run identity recorded on `sweep-skip` baseline rows. There is no run
/// receipt behind such a row; its evidence is the deterministic whole-repo
/// diff that proved the scope unchanged.
pub const SWEEP_RUN_ID: &str = "deterministic-sweep";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum SweepVerdict {
    /// Files under the scope changed since the baseline revision.
    Changed { files: usize },
    /// Whole-repo diff shows no change under the scope since the baseline.
    Current,
    /// The baseline SHA is not reachable in the target's history (rebase,
    /// force-push, shallow clone): the only honest answer is a fresh scan.
    BaselineUnreachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeSweepEntry {
    pub scope_id: String,
    pub phase: WorkflowPhase,
    pub baseline_sha: String,
    pub baseline_dirty: bool,
    pub verdict: SweepVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepReport {
    pub head: RunTargetGitMetadata,
    pub entries: Vec<ScopeSweepEntry>,
    /// Scopes present in the nested-scope tree with no ledger baseline at
    /// all — never scanned, so `no-baseline` means "full scan seeds it".
    pub unbaselined_scopes: Vec<String>,
}

/// Deterministic coverage sweep: for every (scope, phase) baseline, decide
/// whether the scope changed since its recorded revision. Diffs are always
/// whole-repo and filtered per scope afterwards — a pathspec-limited diff
/// can silently advance baselines past unscanned changes.
pub fn sweep_target(target: &Path) -> Result<SweepReport> {
    let head = crate::workspace::target_git_metadata(target)
        .context("sweep requires a git repository target")?;
    let ledger = CoverageLedger::open(target)?;
    let baselines = ledger.latest_baselines()?;
    let scope_paths = scope_path_index(target)?;
    let mut diffs = DiffCache::new(target, &head.sha);
    let entries = baselines
        .iter()
        .map(|row| sweep_entry(row, &head, &scope_paths, &mut diffs))
        .collect::<Result<Vec<_>>>()?;
    Ok(SweepReport {
        unbaselined_scopes: unbaselined_scopes(&scope_paths, &baselines),
        head,
        entries,
    })
}

/// Advance baselines for `Current` entries by writing `sweep-skip` rows at
/// HEAD. Refuses on a dirty tree: a baseline must never claim a revision the
/// working tree does not match. Returns the number of rows written.
pub fn write_sweep_skips(target: &Path, report: &SweepReport) -> Result<usize> {
    anyhow::ensure!(
        !report.head.dirty,
        "refusing --write-skips on a dirty tree; commit or stash first"
    );
    let ledger = CoverageLedger::open(target)?;
    let mut written = 0;
    for entry in current_entries_behind_head(report) {
        ledger.record_baseline(&sweep_skip_row(entry, &report.head)?)?;
        written += 1;
    }
    Ok(written)
}

fn current_entries_behind_head<'report>(
    report: &'report SweepReport,
) -> impl Iterator<Item = &'report ScopeSweepEntry> {
    report.entries.iter().filter(move |entry| {
        entry.verdict == SweepVerdict::Current && entry.baseline_sha != report.head.sha
    })
}

fn sweep_skip_row(entry: &ScopeSweepEntry, head: &RunTargetGitMetadata) -> Result<BaselineRow> {
    Ok(BaselineRow {
        scope_id: entry.scope_id.clone(),
        phase: entry.phase,
        mode: SWEEP_SKIP_MODE.to_string(),
        run_id: SWEEP_RUN_ID.to_string(),
        revision: head.clone(),
        ts_unix: now_unix()?,
    })
}

fn sweep_entry(
    row: &BaselineRow,
    head: &RunTargetGitMetadata,
    scope_paths: &BTreeMap<String, String>,
    diffs: &mut DiffCache<'_>,
) -> Result<ScopeSweepEntry> {
    let verdict = sweep_verdict(row, head, scope_paths, diffs)?;
    Ok(ScopeSweepEntry {
        scope_id: row.scope_id.clone(),
        phase: row.phase,
        baseline_sha: row.revision.sha.clone(),
        baseline_dirty: row.revision.dirty,
        verdict,
    })
}

fn sweep_verdict(
    row: &BaselineRow,
    head: &RunTargetGitMetadata,
    scope_paths: &BTreeMap<String, String>,
    diffs: &mut DiffCache<'_>,
) -> Result<SweepVerdict> {
    if row.revision.sha == head.sha {
        return Ok(SweepVerdict::Current);
    }
    let Some(changed_files) = diffs.changed_files(&row.revision.sha)? else {
        return Ok(SweepVerdict::BaselineUnreachable);
    };
    let changed = scoped_change_count(changed_files, scope_prefix(row, scope_paths));
    Ok(match changed {
        0 => SweepVerdict::Current,
        files => SweepVerdict::Changed { files },
    })
}

fn scope_prefix<'index>(
    row: &BaselineRow,
    scope_paths: &'index BTreeMap<String, String>,
) -> Option<&'index str> {
    if row.scope_id == ROOT_SCOPE_ID {
        return None;
    }
    scope_paths.get(&row.scope_id).map(String::as_str)
}

fn scoped_change_count(changed_files: &[String], prefix: Option<&str>) -> usize {
    match prefix {
        None | Some(".") => changed_files.len(),
        Some(prefix) => changed_files
            .iter()
            .filter(|file| file_under_prefix(file, prefix))
            .count(),
    }
}

fn file_under_prefix(file: &str, prefix: &str) -> bool {
    Path::new(file).starts_with(prefix)
}

fn scope_path_index(target: &Path) -> Result<BTreeMap<String, String>> {
    let Some(tree) = load_nested_project_scopes(target)? else {
        return Ok(BTreeMap::new());
    };
    Ok(tree
        .scopes
        .into_iter()
        .map(|scope| (scope.id, scope.rel_path))
        .collect())
}

fn unbaselined_scopes(
    scope_paths: &BTreeMap<String, String>,
    baselines: &[BaselineRow],
) -> Vec<String> {
    scope_paths
        .keys()
        .filter(|scope_id| !baselines.iter().any(|row| row.scope_id == **scope_id))
        .filter(|scope_id| scope_id.as_str() != ROOT_SCOPE_ID)
        .cloned()
        .collect()
}

/// One whole-repo `git diff --name-only <sha>..HEAD` per distinct baseline
/// SHA, memoized. `None` means the baseline SHA is unreachable.
struct DiffCache<'target> {
    target: &'target Path,
    head_sha: String,
    by_sha: BTreeMap<String, Option<Vec<String>>>,
}

impl<'target> DiffCache<'target> {
    fn new(target: &'target Path, head_sha: &str) -> Self {
        Self {
            target,
            head_sha: head_sha.to_string(),
            by_sha: BTreeMap::new(),
        }
    }

    fn changed_files(&mut self, baseline_sha: &str) -> Result<Option<&[String]>> {
        if !self.by_sha.contains_key(baseline_sha) {
            let diff = whole_repo_diff(self.target, baseline_sha, &self.head_sha)?;
            self.by_sha.insert(baseline_sha.to_string(), diff);
        }
        Ok(self
            .by_sha
            .get(baseline_sha)
            .expect("just inserted")
            .as_deref())
    }
}

fn whole_repo_diff(target: &Path, from: &str, to: &str) -> Result<Option<Vec<String>>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(["diff", "--name-only", &format!("{from}..{to}")])
        .output()
        .context("failed to run git diff for sweep")?;
    if !output.status.success() {
        return Ok(None);
    }
    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect();
    Ok(Some(files))
}

fn now_unix() -> Result<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?;
    Ok(now.as_secs() as i64)
}
