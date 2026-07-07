use crate::event_log::EventKind;
use anyhow::Result;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectionEventRow {
    pub(super) event_hash: String,
    pub(super) event_kind: String,
}

pub(super) fn reject_rekey_cycle(
    original_fp: &str,
    current_fp: &str,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    if seen.insert(current_fp.to_string()) {
        return Ok(());
    }
    anyhow::bail!("rekey chain for {original_fp} contains a cycle at {current_fp}");
}

pub(super) fn rekey_event_hash_after<'a>(
    current_fp: &str,
    watermark: u64,
    events: &'a [ProjectionEventRow],
) -> Result<Option<&'a str>> {
    if events.is_empty() {
        return Ok(None);
    }
    if events.len() == 1 && events[0].event_kind == EventKind::FindingRekeyed.as_str() {
        return Ok(Some(events[0].event_hash.as_str()));
    }
    anyhow::bail!(
        "finding {current_fp} changed after read watermark {watermark}; reload before deciding"
    );
}

pub(super) fn forwarded_rekey_target(original_fp: &str, current_fp: String) -> Option<String> {
    (current_fp != original_fp).then_some(current_fp)
}
