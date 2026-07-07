use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    DecisionCommand, FindingLifecycleWrite, StorageWriterActor, SuppressionEventMeta, WriterCommand,
};
use std::collections::BTreeMap;

/// Rule-based suppression lifecycle event, keyed by finding fingerprint.
/// The `event_kind` is validated by the writer actor to be one of the
/// `Suppression*` kinds.
pub struct SuppressionLifecycleEvent {
    pub event_kind: EventKind,
    pub reason: Option<String>,
    pub rule_id: Option<String>,
    pub statement: Option<String>,
    pub origin: Option<String>,
    pub expires_at_unix: Option<u64>,
    pub actor: String,
}

impl FindingStore {
    /// Current lifecycle status per `stable_fp` from the projection. Absent
    /// entries mean the finding has never had a lifecycle event (default open).
    pub fn current_statuses_for(
        &self,
        stable_fps: &[String],
    ) -> Result<BTreeMap<String, String>> {
        let mut statuses = BTreeMap::new();
        let mut stmt = self
            .conn
            .prepare("select current_status from stable_findings where stable_fp = ?1")?;
        for stable_fp in stable_fps {
            let status: Option<String> = stmt
                .query_row(params![stable_fp], |row| row.get(0))
                .optional()?;
            if let Some(status) = status {
                statuses.insert(stable_fp.clone(), status);
            }
        }
        Ok(statuses)
    }

    /// Append a suppression lifecycle event for the finding identified by
    /// `fingerprint`. Returns `false` when the store is not v3-backed (no-op),
    /// mirroring the audit-event path.
    pub fn append_finding_suppression_event(
        &self,
        fingerprint: &str,
        event: SuppressionLifecycleEvent,
    ) -> Result<bool> {
        let Some(target) =
            self.v3_target_for_fingerprint(fingerprint, "suppression lifecycle event")?
        else {
            return Ok(false);
        };
        StorageWriterActor::commit_blocking(
            target.event_log_dir,
            target.db_path,
            WriterCommand::Decision(DecisionCommand::RecordFindingLifecycle(
                FindingLifecycleWrite {
                    event_kind: event.event_kind,
                    stable_fp: target.stable_fp,
                    reason: event.reason,
                    actor: event.actor,
                    run_id: None,
                    suppression: Some(SuppressionEventMeta {
                        rule_id: event.rule_id,
                        statement: event.statement,
                        origin: event.origin,
                        expires_at_unix: event.expires_at_unix,
                    }),
                },
            )),
        )?;
        Ok(true)
    }
}
