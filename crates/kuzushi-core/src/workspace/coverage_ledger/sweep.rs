use super::store::{BaselineRow, CoverageLedger};
use super::SWEEP_SKIP_MODE;
use crate::modules::WorkflowPhase;
use crate::run_artifacts::RunTargetGitMetadata;
use crate::workspace::{load_nested_project_scopes, ROOT_SCOPE_ID};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
mod git;
use super::cancellation::check as check_cancelled;

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
    /// Git cannot compare the baseline revision with the current commit.
    BaselineUnreachable,
    /// Commit metadata cannot identify the exact source represented by this row.
    SourceUnverified { reason: SourceCheckIssue },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceCheckIssue {
    DirtyWorkingTree,
    DirtyBaseline,
    ScopeUnavailable,
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
    /// Root or nested scopes with no ledger baseline. Absence is not proof
    /// that no scan has ever been attempted.
    pub unbaselined_scopes: Vec<String>,
}

/// Deterministic coverage sweep: for every (scope, phase) baseline, decide
/// whether the scope changed since its recorded revision. Diffs are always
/// whole-repo and filtered per scope afterwards — a pathspec-limited diff
/// can silently advance baselines past unscanned changes.
pub fn sweep_target(target: &Path) -> Result<SweepReport> {
    sweep_target_with_cancellation(target, None)
}

pub(crate) fn sweep_target_with_cancellation(
    target: &Path,
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<SweepReport> {
    check_cancelled(cancellation)?;
    let head = git::metadata(target, cancellation)?;
    let baselines = match CoverageLedger::open_if_exists(target)? {
        Some(ledger) => ledger.latest_baselines_with_cancellation(cancellation)?,
        None => Vec::new(),
    };
    let scope_paths = scope_path_index(target)?;
    let mut diffs = DiffCache::new(target, &head.sha, cancellation);
    let entries = baselines
        .iter()
        .map(|row| {
            check_cancelled(cancellation)?;
            sweep_entry(row, &head, &scope_paths, &mut diffs)
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        git::metadata(target, cancellation)? == head,
        "source changed during baseline inspection; run coverage:sweep again"
    );
    Ok(SweepReport {
        unbaselined_scopes: unbaselined_scopes(&scope_paths, &baselines, cancellation)?,
        head,
        entries,
    })
}

/// Advance baselines for `Current` entries by writing `sweep-skip` rows at
/// HEAD. Refuses on a dirty tree: a baseline must never claim a revision the
/// working tree does not match. Returns the number of rows written.
pub fn write_sweep_skips(target: &Path, report: &SweepReport) -> Result<usize> {
    write_sweep_skips_with_cancellation(target, report, None)
}

pub(crate) fn write_sweep_skips_with_cancellation(
    target: &Path,
    report: &SweepReport,
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<usize> {
    check_cancelled(cancellation)?;
    anyhow::ensure!(
        !report.head.dirty,
        "refusing --write-skips on a dirty tree; commit or stash first"
    );
    anyhow::ensure!(
        sweep_target_with_cancellation(target, cancellation)? == *report,
        "source or baseline state changed; run coverage:sweep again before writing skips"
    );
    write_skips(
        target,
        report,
        current_entries_behind_head(report),
        cancellation,
    )
}

pub(super) fn write_skips<'a>(
    target: &Path,
    report: &SweepReport,
    entries: impl Iterator<Item = &'a ScopeSweepEntry>,
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<usize> {
    check_cancelled(cancellation)?;
    let ledger = CoverageLedger::open(target)?;
    let transaction = ledger.connection().unchecked_transaction()?;
    let mut written = 0;
    for entry in entries {
        check_cancelled(cancellation)?;
        ledger.record_baseline(&sweep_skip_row(entry, &report.head)?)?;
        written += 1;
    }
    anyhow::ensure!(
        git::metadata(target, cancellation)? == report.head,
        "source changed while writing sweep skips; no skip rows were committed"
    );
    check_cancelled(cancellation)?;
    transaction.commit()?;
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
    if let Some(reason) = source_check_issue(row, head, scope_paths) {
        return Ok(SweepVerdict::SourceUnverified { reason });
    }
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

fn source_check_issue(
    row: &BaselineRow,
    head: &RunTargetGitMetadata,
    scope_paths: &BTreeMap<String, String>,
) -> Option<SourceCheckIssue> {
    if head.dirty {
        return Some(SourceCheckIssue::DirtyWorkingTree);
    }
    if row.revision.dirty {
        return Some(SourceCheckIssue::DirtyBaseline);
    }
    (row.scope_id != ROOT_SCOPE_ID && !scope_paths.contains_key(&row.scope_id))
        .then_some(SourceCheckIssue::ScopeUnavailable)
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
    let mut paths = BTreeMap::from([(ROOT_SCOPE_ID.to_string(), ".".to_string())]);
    let Some(tree) = load_nested_project_scopes(target)? else {
        return Ok(paths);
    };
    paths.extend(
        tree.scopes
            .into_iter()
            .map(|scope| (scope.id, scope.rel_path)),
    );
    Ok(paths)
}

fn unbaselined_scopes(
    scope_paths: &BTreeMap<String, String>,
    baselines: &[BaselineRow],
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<Vec<String>> {
    let known: BTreeSet<_> = baselines.iter().map(|row| row.scope_id.as_str()).collect();
    let mut missing = Vec::new();
    for scope in scope_paths.keys() {
        check_cancelled(cancellation)?;
        if !known.contains(scope.as_str()) {
            missing.push(scope.clone());
        }
    }
    Ok(missing)
}

/// One whole-repo `git diff --name-only <sha>..HEAD` per distinct baseline
/// SHA, memoized. `None` means the baseline SHA is unreachable.
struct DiffCache<'target> {
    target: &'target Path,
    head_sha: String,
    by_sha: BTreeMap<String, Option<Vec<String>>>,
    cancellation: Option<&'target crate::ScanCancellation>,
}

impl<'target> DiffCache<'target> {
    fn new(
        target: &'target Path,
        head_sha: &str,
        cancellation: Option<&'target crate::ScanCancellation>,
    ) -> Self {
        Self {
            target,
            head_sha: head_sha.to_string(),
            by_sha: BTreeMap::new(),
            cancellation,
        }
    }

    fn changed_files(&mut self, baseline_sha: &str) -> Result<Option<&[String]>> {
        if !self.by_sha.contains_key(baseline_sha) {
            let diff =
                whole_repo_diff(self.target, baseline_sha, &self.head_sha, self.cancellation)?;
            self.by_sha.insert(baseline_sha.to_string(), diff);
        }
        let diff = self
            .by_sha
            .get(baseline_sha)
            .context("Baseline diff disappeared after inspection")?;
        Ok(diff.as_deref())
    }
}

use git::whole_repo_diff;

fn now_unix() -> Result<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?;
    Ok(now.as_secs() as i64)
}
