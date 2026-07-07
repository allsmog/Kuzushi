//! Re-scan reconciler: the ONLY emitter of `FindingDisappeared`.
//!
//! After a scan run completes successfully, this diffs the identities observed
//! in prior runs against the just-completed run and marks the vanished ones
//! stale — but only when the *tool that produced the finding actually ran in
//! the completed scan* (per-tool scoping). This is what makes `Fixed`/`Removed`
//! an honest, machine-computed fact rather than a human assertion: a finding is
//! only "gone" if a re-run of its own engine no longer produces it.
//!
//! Safety rules:
//! - Failed runs never reconcile (the caller guards on status).
//! - A tool is only considered "exercised" if it produced at least one
//!   observation in the completed run. This is conservative: a tool that ran
//!   and found nothing will not stale its prior findings (a missed `Fixed`,
//!   never a fabricated one). This deliberately favours false-negatives over
//!   the fabricated-`Fixed` failure mode the product forbids.
//! - Reconciling the same run twice is a no-op: `FindingDisappeared` flips
//!   `current_status` to `stale`, and only `open` findings are candidates.

use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    DecisionCommand, FindingLifecycleWrite, StorageWriterActor, WriterCommand,
};
use std::collections::BTreeSet;

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
}

impl FindingStore {
    /// Marks findings that vanished in `completed_run_id` as disappeared,
    /// scoped to tools the completed run actually exercised.
    pub(crate) fn reconcile_disappeared_findings(
        &self,
        completed_run_id: &str,
    ) -> Result<RescanReconciliation> {
        if self.v3_storage_paths().is_none() {
            return Ok(RescanReconciliation::default());
        }
        let tools = self.tools_exercised_by_run(completed_run_id)?;
        if tools.is_empty() {
            return Ok(RescanReconciliation::default());
        }
        let mut disappeared = Vec::new();
        for candidate in self.candidate_stale_identities(completed_run_id, &tools)? {
            self.emit_disappearance(completed_run_id, &candidate)?;
            disappeared.push(candidate.stable_fp);
        }
        Ok(RescanReconciliation {
            disappeared,
            tools_exercised: tools.into_iter().collect(),
        })
    }

    fn tools_exercised_by_run(&self, run_id: &str) -> Result<BTreeSet<String>> {
        let mut stmt = self
            .conn
            .prepare("select distinct tool from finding_observations where run_id = ?1")?;
        let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<BTreeSet<_>>>()
            .context("Could not list tools exercised by run")
    }

    fn candidate_stale_identities(
        &self,
        run_id: &str,
        tools: &BTreeSet<String>,
    ) -> Result<Vec<StaleCandidate>> {
        let mut stmt = self.conn.prepare(
            r#"
            select o.stable_fp, o.tool, o.run_id
              from finding_observations o
              join stable_findings sf on sf.stable_fp = o.stable_fp
              join (
                    select stable_fp, max(created_seq) as mx
                      from finding_observations
                     group by stable_fp
                   ) last
                on last.stable_fp = o.stable_fp and last.mx = o.created_seq
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
            })
        })?;
        let candidates = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list stale finding candidates")?;
        Ok(candidates
            .into_iter()
            .filter(|candidate| tools.contains(&candidate.tool))
            .collect())
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
                    tool: Some(candidate.tool.clone()),
                    last_seen_run_id: Some(candidate.last_seen_run_id.clone()),
                    reconciled_against_run_id: Some(run_id.to_string()),
                },
            )),
        )?;
        Ok(())
    }
}
