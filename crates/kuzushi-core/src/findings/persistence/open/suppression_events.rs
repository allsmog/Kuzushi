use super::*;
use crate::event_log::{EventKind, EventLog};
use crate::storage_v3::writer_actor::{
    DecisionCommand, FindingLifecycleWrite, StorageWriterActor, SuppressionEventMeta, WriterCommand,
};
use std::collections::{BTreeMap, BTreeSet};

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
    pub fn current_statuses_for(&self, stable_fps: &[String]) -> Result<BTreeMap<String, String>> {
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

    /// For each requested `stable_fp` that is *currently suppressed by a rule*,
    /// return the id of the rule that suppressed it. A finding is rule-suppressed
    /// iff its latest suppression-lifecycle event is a `SuppressionAdded` whose
    /// payload carries a `ruleId`. Manual `decision suppressed` events (from
    /// `DecisionWrite`) carry no `ruleId`, so they are never returned — this is
    /// what keeps the reopen paths from ever undoing a human dismissal.
    pub fn rule_originated_suppression_ids(
        &self,
        stable_fps: &[String],
    ) -> Result<BTreeMap<String, String>> {
        let Some(dir) = &self.event_log_dir else {
            return Ok(BTreeMap::new());
        };
        if !dir.exists() {
            return Ok(BTreeMap::new());
        }
        let wanted: BTreeSet<&str> = stable_fps.iter().map(String::as_str).collect();
        let log = EventLog::open(dir)?;
        let mut latest: BTreeMap<String, LatestSuppression> = BTreeMap::new();
        for event in log.read_all()? {
            if !is_suppression_lifecycle(event.event_kind) {
                continue;
            }
            let Some(stable_fp) = event.payload.get("stableFp").and_then(|v| v.as_str()) else {
                continue;
            };
            if !wanted.contains(stable_fp) {
                continue;
            }
            let rule_id = event
                .payload
                .get("ruleId")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            latest.insert(
                stable_fp.to_string(),
                LatestSuppression {
                    kind: event.event_kind,
                    rule_id,
                },
            );
        }
        Ok(rule_originated(latest))
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
                    tool: None,
                    last_seen_run_id: None,
                    reconciled_against_run_id: None,
                },
            )),
        )?;
        Ok(true)
    }
}

struct LatestSuppression {
    kind: EventKind,
    rule_id: Option<String>,
}

fn is_suppression_lifecycle(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::SuppressionAdded | EventKind::SuppressionExpired | EventKind::SuppressionRemoved
    )
}

/// A finding is rule-suppressed iff its latest suppression event is a
/// `SuppressionAdded` carrying a `ruleId`.
fn rule_originated(latest: BTreeMap<String, LatestSuppression>) -> BTreeMap<String, String> {
    latest
        .into_iter()
        .filter_map(|(stable_fp, entry)| match entry {
            LatestSuppression {
                kind: EventKind::SuppressionAdded,
                rule_id: Some(rule_id),
            } => Some((stable_fp, rule_id)),
            _ => None,
        })
        .collect()
}
