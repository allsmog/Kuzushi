use crate::event_log::EventKind;
use crate::findings::{FindingStore, SuppressionLifecycleEvent};
use crate::suppressions::domain::{SuppressionReport, SuppressionState};
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct SuppressionReconcileSummary {
    pub added: usize,
    pub expired: usize,
    pub removed: usize,
}

impl SuppressionReconcileSummary {
    pub fn is_noop(&self) -> bool {
        self.added == 0 && self.expired == 0 && self.removed == 0
    }
}

/// Diff desired suppression state (from evaluation) against the projected
/// `current_status` and append only the delta. Idempotent: a second call over
/// unchanged state appends zero events.
///
/// - Newly-active matches emit `SuppressionAdded`.
/// - A finding whose suppressing rule lapsed emits `SuppressionExpired`.
/// - A finding that no longer matches any rule emits `SuppressionRemoved`
///   (e.g. an ignore comment was deleted, or a host came back in scope).
///
/// Both reopen paths only ever touch **rule-originated** suppressions — a
/// finding whose latest suppression event carries a `ruleId`. A manual
/// `decision suppressed` (no `ruleId`) is never reopened here, so a human's
/// dismissal is never silently undone even if a broad rule coincidentally
/// matched the same finding.
pub fn reconcile_suppression_events(
    store: &FindingStore,
    report: &SuppressionReport,
    actor: &str,
) -> Result<SuppressionReconcileSummary> {
    let stable_fps = report
        .states
        .iter()
        .map(|entry| entry.stable_fp.clone())
        .collect::<Vec<_>>();
    let statuses = store.current_statuses_for(&stable_fps)?;
    let rule_suppressions = store.rule_originated_suppression_ids(&stable_fps)?;
    let mut summary = SuppressionReconcileSummary::default();
    for entry in &report.states {
        let is_suppressed = statuses.get(&entry.stable_fp).map(String::as_str) == Some("suppressed");
        let suppressing_rule = rule_suppressions.get(&entry.stable_fp);
        apply_state_delta(store, entry, is_suppressed, suppressing_rule, actor, &mut summary)?;
    }
    Ok(summary)
}

fn apply_state_delta(
    store: &FindingStore,
    entry: &crate::suppressions::domain::SuppressionStateEntry,
    is_suppressed: bool,
    suppressing_rule: Option<&String>,
    actor: &str,
    summary: &mut SuppressionReconcileSummary,
) -> Result<()> {
    match &entry.state {
        SuppressionState::Active(matched) if !is_suppressed => {
            store.append_finding_suppression_event(&entry.fingerprint, added_event(matched, actor))?;
            summary.added += 1;
        }
        SuppressionState::Expired { rule_id, .. } if suppressing_rule.is_some() => {
            store.append_finding_suppression_event(&entry.fingerprint, expired_event(rule_id, actor))?;
            summary.expired += 1;
        }
        SuppressionState::None if suppressing_rule.is_some() => {
            let rule_id = suppressing_rule.expect("guarded by is_some");
            store.append_finding_suppression_event(&entry.fingerprint, removed_event(rule_id, actor))?;
            summary.removed += 1;
        }
        _ => {}
    }
    Ok(())
}

fn added_event(
    matched: &crate::suppressions::domain::SuppressionMatch,
    actor: &str,
) -> SuppressionLifecycleEvent {
    SuppressionLifecycleEvent {
        event_kind: EventKind::SuppressionAdded,
        reason: Some(matched.reason.as_str().to_string()),
        rule_id: Some(matched.rule_id.clone()),
        statement: Some(matched.statement.clone()),
        origin: Some(matched.origin.as_str().to_string()),
        expires_at_unix: matched.expires_at_unix,
        actor: actor.to_string(),
    }
}

fn expired_event(rule_id: &str, actor: &str) -> SuppressionLifecycleEvent {
    SuppressionLifecycleEvent {
        event_kind: EventKind::SuppressionExpired,
        reason: None,
        rule_id: Some(rule_id.to_string()),
        statement: None,
        origin: None,
        expires_at_unix: None,
        actor: actor.to_string(),
    }
}

fn removed_event(rule_id: &str, actor: &str) -> SuppressionLifecycleEvent {
    SuppressionLifecycleEvent {
        event_kind: EventKind::SuppressionRemoved,
        reason: None,
        rule_id: Some(rule_id.to_string()),
        statement: None,
        origin: None,
        expires_at_unix: None,
        actor: actor.to_string(),
    }
}
