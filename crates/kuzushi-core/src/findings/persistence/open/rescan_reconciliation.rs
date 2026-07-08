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
//!    reconcilable (`is_deterministic_scanner`). Non-deterministic/agentic
//!    engines (`taint-iris*`, `agentic-sast`, `carlini-*`, `variant`, `ndiff`,
//!    `exploit-chain`) NEVER retire a finding: a re-hunt that happens not to
//!    re-surface a real bug must not report it Fixed. Unknown tools are treated
//!    as non-deterministic (conservative default).
//! 2. **Scope parity.** A finding is only retired when the completed run's scan
//!    target is byte-identical to the finding's last-seen run target. A
//!    subdir-scoped `semgrep target=<subdir>` re-run therefore cannot stale a
//!    finding whose origin run scanned the whole target.
//! 3. **Completed runs only.** The caller reconciles solely on `completed`
//!    status (allowlist), so failed/canceled/partial runs never reconcile.
//!
//! Reconciling the same run twice is a no-op: `FindingDisappeared` flips
//! `current_status` to `stale`, and only `open` findings are candidates.

use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    DecisionCommand, FindingLifecycleWrite, StorageWriterActor, WriterCommand,
};
use std::collections::BTreeSet;

/// Reproducible static scanners whose absence in a same-scope re-run is honest
/// evidence a finding is gone. Deliberately a whitelist: an unlisted (possibly
/// agentic or new) tool is treated as non-deterministic and never retires a
/// finding — a missed `Fixed` is acceptable, a fabricated one is not.
const DETERMINISTIC_SCANNERS: &[&str] = &[
    "semgrep",
    "codeql",
    "dep-hygiene",
    "secret-scan",
    "cargo-audit",
    "license-scan",
    "sbom-scan",
    "iac-scan",
];

fn is_deterministic_scanner(tool: &str) -> bool {
    DETERMINISTIC_SCANNERS.contains(&tool)
}

/// Outcome of one reconciliation pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RescanReconciliation {
    /// Stable fingerprints newly marked stale (disappeared) by this run.
    pub disappeared: Vec<String>,
    /// Tools exercised by the completed run (per-tool scoping evidence).
    pub tools_exercised: Vec<String>,
}

struct StaleCandidate {
    stable_fp: String,
    tool: String,
    last_seen_run_id: String,
    origin_target: Option<String>,
}

impl StaleCandidate {
    /// A candidate may be retired only when its tool ran in the completed scan,
    /// is a deterministic scanner, and the completed run scanned the same scope
    /// (target path) that last observed the finding.
    fn is_reconcilable(&self, tools: &BTreeSet<String>, completed_target: &str) -> bool {
        tools.contains(&self.tool)
            && is_deterministic_scanner(&self.tool)
            && self.origin_target.as_deref() == Some(completed_target)
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
        let Some(completed_target) = self.run_target(completed_run_id)? else {
            // Unknown scope → cannot establish parity → never reconcile.
            return Ok(RescanReconciliation::default());
        };
        let tools = self.tools_exercised_by_run(completed_run_id)?;
        if tools.is_empty() {
            return Ok(RescanReconciliation::default());
        }
        let disappeared = self.retire_candidates(completed_run_id, &tools, &completed_target)?;
        Ok(RescanReconciliation {
            disappeared,
            tools_exercised: tools.into_iter().collect(),
        })
    }

    fn retire_candidates(
        &self,
        run_id: &str,
        tools: &BTreeSet<String>,
        completed_target: &str,
    ) -> Result<Vec<String>> {
        let mut disappeared = Vec::new();
        for candidate in self.candidate_stale_identities(run_id)? {
            if !candidate.is_reconcilable(tools, completed_target) {
                continue;
            }
            self.emit_disappearance(run_id, &candidate)?;
            disappeared.push(candidate.stable_fp);
        }
        Ok(disappeared)
    }

    /// The scanned target path recorded for `run_id`, if known.
    fn run_target(&self, run_id: &str) -> Result<Option<String>> {
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

    fn tools_exercised_by_run(&self, run_id: &str) -> Result<BTreeSet<String>> {
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
            select o.stable_fp, o.tool, o.run_id, rs.target
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
