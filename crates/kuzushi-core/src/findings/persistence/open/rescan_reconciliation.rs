//! Re-scan reconciler: the ONLY emitter of `FindingDisappeared`.
//!
//! After a scan run completes successfully, this diffs the identities observed
//! in prior runs against the just-completed run and marks the vanished ones
//! stale. `Fixed`/`Removed` are computed from this, never asserted by a human,
//! so the reconciler is the load-bearing honesty boundary: a finding is only
//! "gone" if a re-run of its own engine, over the SAME scope, no longer
//! produces it.
//!
//! Three structural guards keep a partial/flaky re-run from fabricating a
//! `Fixed`/`Removed`:
//! 1. **Deterministic tools only.** Only reproducible static scanners are
//!    reconcilable (`all_components_deterministic`). Non-deterministic/agentic
//!    engines (`taint-iris*`, `agentic-sast`, `carlini-*`, `variant`, `ndiff`,
//!    `exploit-chain`) NEVER retire a finding: a re-hunt that happens not to
//!    re-surface a real bug must not report it Fixed. Unknown tools are treated
//!    as non-deterministic (conservative default). Deduplication can merge
//!    several engines into one comma-joined tool, so the test is over ALL
//!    components: every one must be deterministic and every one must have run
//!    evidence, which makes one agentic component permanently unretirable.
//! 2. **Scope parity.** A finding is only retired when the completed run's scan
//!    target is byte-identical to the finding's last-seen run target AND the
//!    completed run's recorded scan paths (its durable Scan stage receipt)
//!    cover the finding's file. A subdir-scoped re-run therefore cannot stale
//!    a finding it never re-examined, whether the restriction was a different
//!    target or a `paths=[…]` selection over the same target. Recorded scope is
//!    three-way, never two: a store with no artifact root at all (in-memory)
//!    means whole-target, an existing run directory without a Scan receipt
//!    means whole-target, and a *missing* run directory means unknown — so a
//!    pruned run (`kz runs prune` deletes the whole directory while the
//!    observations survive) retires nothing instead of reading as whole-target.
//!    Runs from before run directories existed degrade the same fail-closed way.
//! 3. **Completed runs only.** The caller reconciles solely on `completed`
//!    status (allowlist), so failed/canceled/partial runs never reconcile.
//!
//! Reconciling the same run twice is a no-op: `FindingDisappeared` flips
//! `current_status` to `stale`, and only `open` findings are candidates.

use super::*;
use crate::event_log::EventKind;
use crate::findings::{all_components_deterministic, tool_components};
use crate::run_artifacts::{ScanEngineStageOutcome, ScanStageData};
use crate::storage_v3::writer_actor::{
    DecisionCommand, FindingLifecycleWrite, StorageWriterActor, WriterCommand,
};
use std::collections::BTreeSet;

/// Outcome of one reconciliation pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RescanReconciliation {
    /// Stable fingerprints newly marked stale (disappeared) by this run.
    pub disappeared: Vec<String>,
    /// Engines the completed run proved it exercised (per-engine scoping
    /// evidence): observed tool components plus receipt-completed engines.
    pub tools_exercised: Vec<String>,
}

struct StaleCandidate {
    stable_fp: String,
    tool: String,
    last_seen_run_id: String,
    origin_target: Option<String>,
    path: Option<String>,
}

impl StaleCandidate {
    /// A candidate may be retired only when EVERY engine behind its tool is a
    /// deterministic scanner with run evidence in the completed scan, and that
    /// scan covered the same scope (target and, for a path-restricted scan, the
    /// finding's file) that last observed the finding. A merged tool is as
    /// retirable as its weakest component, never as its strongest.
    fn is_reconcilable(&self, tools: &BTreeSet<String>, scope: &CompletedScanScope) -> bool {
        all_components_deterministic(&self.tool)
            && tool_components(&self.tool).all(|component| tools.contains(component))
            && scope.covers(self)
    }
}

/// Scope of a completed scan: the target it ran over and, when the scan was
/// path-restricted (recorded in its durable Scan stage receipt), the paths it
/// actually examined. An empty path list means the whole target was scanned.
pub(crate) struct CompletedScanScope {
    target: String,
    paths: Vec<String>,
    /// Engines the Scan stage receipt records as having completed, which is the
    /// only evidence a clean re-run of an engine leaves behind.
    receipt_engines: BTreeSet<String>,
}

impl CompletedScanScope {
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    fn covers(&self, candidate: &StaleCandidate) -> bool {
        if candidate.origin_target.as_deref() != Some(self.target.as_str()) {
            return false;
        }
        if self.paths.is_empty() {
            return true;
        }
        // A path-restricted scan can only retire findings whose file it
        // provably re-examined; an unknown finding path is never covered.
        candidate
            .path
            .as_deref()
            .is_some_and(|path| self.covers_file(path))
    }

    /// Whether a finding at `file_path` (absolute or target-relative) lies
    /// within the recorded scan paths. Whole-target scans cover every file; a
    /// path that cannot be resolved inside the target is never covered.
    pub(crate) fn covers_file(&self, file_path: &str) -> bool {
        crate::run_artifacts::scan_paths_cover_file(&self.target, &self.paths, file_path)
    }
}

/// The scope half a completed run's durable Scan stage receipt carries.
#[derive(Default)]
struct RecordedScanEvidence {
    paths: Vec<String>,
    engines: BTreeSet<String>,
}

/// Only engines the receipt records as `Complete` prove a re-examination: a
/// partial, skipped, or failed engine stage examined an unknown subset.
fn receipt_scan_evidence(scan: ScanStageData) -> RecordedScanEvidence {
    RecordedScanEvidence {
        paths: scan.scope.paths,
        engines: scan
            .engines
            .into_iter()
            .filter(|engine| engine.outcome == ScanEngineStageOutcome::Complete)
            .map(|engine| engine.engine)
            .collect(),
    }
}

impl FindingStore {
    /// Marks findings that vanished in `completed_run_id` as disappeared, scoped
    /// to deterministic tools the completed run exercised over the same target.
    pub(crate) fn reconcile_disappeared_findings(
        &self,
        completed_run_id: &str,
    ) -> Result<RescanReconciliation> {
        if self.v3_storage_paths().is_none() {
            return Ok(RescanReconciliation::default());
        }
        let Some(scope) = self.completed_scan_scope(completed_run_id)? else {
            // Unknown scope → cannot establish parity → never reconcile.
            return Ok(RescanReconciliation::default());
        };
        let tools = self.engines_proven_by_run(completed_run_id, &scope)?;
        if tools.is_empty() {
            return Ok(RescanReconciliation::default());
        }
        let disappeared = self.retire_candidates(completed_run_id, &tools, &scope)?;
        Ok(RescanReconciliation {
            disappeared,
            tools_exercised: tools.into_iter().collect(),
        })
    }

    fn retire_candidates(
        &self,
        run_id: &str,
        tools: &BTreeSet<String>,
        scope: &CompletedScanScope,
    ) -> Result<Vec<String>> {
        let mut disappeared = Vec::new();
        for candidate in self.candidate_stale_identities(run_id)? {
            if !candidate.is_reconcilable(tools, scope) {
                continue;
            }
            self.emit_disappearance(run_id, &candidate)?;
            disappeared.push(candidate.stable_fp);
        }
        Ok(disappeared)
    }

    /// The full recorded scope of a completed run: `None` when the target is
    /// unknown, the run's artifacts are gone, or its Scan stage receipt exists
    /// but cannot be read — each means parity cannot be established, so nothing
    /// is retired.
    pub(crate) fn completed_scan_scope(
        &self,
        run_id: &str,
    ) -> Result<Option<CompletedScanScope>> {
        let Some(target) = self.run_target(run_id)? else {
            return Ok(None);
        };
        match self.recorded_scan_evidence(run_id) {
            Ok(Some(evidence)) => Ok(Some(CompletedScanScope {
                target,
                paths: evidence.paths,
                receipt_engines: evidence.engines,
            })),
            Ok(None) | Err(_) => Ok(None),
        }
    }

    /// What the run's durable Scan stage receipt proves: `None` when the run's
    /// artifacts are gone (pruned or never materialized), so its scope cannot be
    /// established. An existing run directory without a Scan receipt (single-tool
    /// runs) means the whole target and no receipt-backed engines.
    fn recorded_scan_evidence(&self, run_id: &str) -> Result<Option<RecordedScanEvidence>> {
        let Some(root) = self.v3_workspace_root() else {
            return Ok(Some(RecordedScanEvidence::default()));
        };
        // Validate the id before the directory probe so a separator-bearing
        // run id can never satisfy the existence check against a directory
        // outside the runs root — traversal safety must be local, not an
        // accident of the checked receipt read below.
        if crate::run_artifacts::RunId::parse(run_id).is_err() {
            return Ok(None);
        }
        if !crate::run_artifacts::run_dir(&root, run_id).is_dir() {
            return Ok(None);
        }
        let receipt = crate::run_artifacts::load_scan_stage_data(&root, run_id)?;
        Ok(Some(
            receipt
                .and_then(|receipt| receipt.scan)
                .map(receipt_scan_evidence)
                .unwrap_or_default(),
        ))
    }

    /// Engines the run provably exercised: those that produced an observation
    /// plus those its Scan receipt records as completed. A clean re-run leaves no
    /// observation, so without the receipt half an engine that ran and found
    /// nothing would look like an engine that never ran.
    ///
    /// Expanding merged observation tools (`"codeql,semgrep"`) into component
    /// evidence is sound only because dedup collision merges are scoped to one
    /// scan run: a merged tool on this run's observation means every component
    /// produced a finding in THIS run. A caller that re-persisted an
    /// already-merged stored finding under a fresh run id would break that
    /// premise and mint evidence for engines that never ran.
    pub(crate) fn engines_proven_by_run(
        &self,
        run_id: &str,
        scope: &CompletedScanScope,
    ) -> Result<BTreeSet<String>> {
        let observed = self.tools_exercised_by_run(run_id)?;
        Ok(observed
            .iter()
            .flat_map(|tool| tool_components(tool).map(str::to_string))
            .chain(scope.receipt_engines.iter().cloned())
            .collect())
    }

    pub(crate) fn scan_reassessment_receipt(
        &self, run_id: &str,
    ) -> Result<Option<crate::run_artifacts::PhaseStageReceipt>> {
        let Some(root) = self.v3_workspace_root() else { return Ok(None); };
        crate::run_artifacts::load_scan_stage_data(root, run_id)
    }

    /// The scanned target path recorded for `run_id`, if known.
    pub(crate) fn run_target(&self, run_id: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "select target from run_states where run_id = ?1",
                params![run_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map(Option::flatten)
            .context("Could not load run target")
    }

    pub(crate) fn tools_exercised_by_run(&self, run_id: &str) -> Result<BTreeSet<String>> {
        let mut stmt = self
            .conn
            .prepare("select distinct tool from finding_observations where run_id = ?1")?;
        let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<BTreeSet<_>>>()
            .context("Could not list tools exercised by run")
    }

    fn candidate_stale_identities(&self, run_id: &str) -> Result<Vec<StaleCandidate>> {
        let mut stmt = self.conn.prepare(
            r#"
            select o.stable_fp, o.tool, o.run_id, rs.target, o.display_path
              from finding_observations o
              join stable_findings sf on sf.stable_fp = o.stable_fp
              join (
                    select stable_fp, max(created_seq) as mx
                      from finding_observations
                     group by stable_fp
                   ) last
                on last.stable_fp = o.stable_fp and last.mx = o.created_seq
              left join run_states rs on rs.run_id = o.run_id
             where sf.current_status = 'open'
               and not exists (
                     select 1 from finding_observations x
                      where x.stable_fp = o.stable_fp and x.run_id = ?1
                   )
            "#,
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok(StaleCandidate {
                stable_fp: row.get(0)?,
                tool: row.get(1)?,
                last_seen_run_id: row.get(2)?,
                origin_target: row.get(3)?,
                path: row.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list stale finding candidates")
    }

    fn emit_disappearance(&self, run_id: &str, candidate: &StaleCandidate) -> Result<()> {
        let (event_log_dir, db_path) =
            self.required_v3_storage_paths("reconcile disappeared findings")?;
        StorageWriterActor::commit_blocking(
            event_log_dir,
            db_path,
            WriterCommand::Decision(DecisionCommand::RecordFindingLifecycle(
                FindingLifecycleWrite {
                    event_kind: EventKind::FindingDisappeared,
                    stable_fp: candidate.stable_fp.clone(),
                    reason: Some("rescan-disappeared".to_string()),
                    actor: "rescan-reconciler".to_string(),
                    run_id: Some(run_id.to_string()),
                    suppression: None,
                    tool: Some(candidate.tool.clone()),
                    last_seen_run_id: Some(candidate.last_seen_run_id.clone()),
                    reconciled_against_run_id: Some(run_id.to_string()),
                },
            )),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_over_paths(paths: &[&str]) -> CompletedScanScope {
        CompletedScanScope {
            target: "/tmp/repo".to_string(),
            paths: paths.iter().map(|path| path.to_string()).collect(),
            receipt_engines: BTreeSet::new(),
        }
    }

    #[test]
    fn parent_dir_segments_never_extend_scan_scope_coverage() {
        assert!(
            !scope_over_paths(&["lib"]).covers_file("lib/../secret/x.ts"),
            "a `..` hop out of lib/ leaves the scanned scope"
        );
        assert!(scope_over_paths(&["src"]).covers_file("lib/../src/x.ts"));
    }

    #[test]
    fn dot_segments_and_duplicate_slashes_normalize_before_scope_matching() {
        let scope = scope_over_paths(&["src/util"]);
        assert!(scope.covers_file("src/./util//x.ts"));
        assert!(scope.covers_file("/tmp/repo/src/util/x.ts"));
        assert!(!scope.covers_file("src/./other/x.ts"));
    }

    #[test]
    fn paths_escaping_or_outside_the_target_are_never_covered() {
        let scope = scope_over_paths(&["outside", "elsewhere"]);
        assert!(!scope.covers_file("../outside/x.ts"));
        assert!(!scope.covers_file("/elsewhere/x.ts"));
    }

    #[test]
    fn scope_entries_with_parent_segments_prove_nothing() {
        let scope = scope_over_paths(&["lib/.."]);
        assert!(!scope.covers_file("lib/util.ts"));
        assert!(!scope.covers_file("src/app.ts"));
    }
}
