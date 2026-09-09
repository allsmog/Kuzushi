use super::*;
use crate::session_transcript::ConversationSnapshot;

const RECENT_SESSION_LIMIT: usize = 64;
const RECOVERY_BYTE_LIMIT: usize = 32 * 1024 * 1024;

struct Candidate {
    timestamp: String,
    sequence: u64,
    snapshot: Option<ConversationSnapshot>,
}

impl SessionTranscriptStore {
    /// Recover from the most recent 64 operator-owned sessions, with bounded IO.
    /// Clear events are tombstones; unreadable records never silently fall back.
    pub fn recover_conversation(
        &self,
        target: &Path,
        current_session: &Path,
    ) -> Result<Option<ConversationSnapshot>> {
        let mut files = self.session_files()?;
        files.sort();
        let mut remaining = RECOVERY_BYTE_LIMIT;
        let mut candidate = None;
        for path in files
            .into_iter()
            .rev()
            .filter(|p| p != current_session)
            .take(RECENT_SESSION_LIMIT)
        {
            let Some(records) = recovery_records(&path, &mut remaining)? else {
                continue;
            };
            select_candidate(&records, target, &mut candidate)?;
        }
        Ok(candidate.and_then(|value: Candidate| value.snapshot))
    }
}

fn recovery_records(path: &Path, remaining: &mut usize) -> Result<Option<Vec<SessionRecord>>> {
    let raw = discovery::read_session_file_bounded(path, (*remaining).min(8 * 1024 * 1024))?;
    *remaining = remaining.saturating_sub(raw.len());
    let (records, warnings) = parse_records(&raw);
    let summary = summarize(path, &records, warnings.len())?;
    if matches!(
        summary.status,
        SessionStatus::Running | SessionStatus::Unknown
    ) {
        return Ok(None);
    }
    // A process may be writing its last line. Do not use a partially written
    // transcript to reconstruct a conversation or bypass a clear event.
    anyhow::ensure!(
        warnings.is_empty(),
        "session history is incomplete; recovery was not applied"
    );
    Ok(Some(records))
}

fn select_candidate(
    records: &[SessionRecord],
    target: &Path,
    selected: &mut Option<Candidate>,
) -> Result<()> {
    for record in records {
        let Some(snapshot) = conversation_event(record, target)? else {
            continue;
        };
        if selected
            .as_ref()
            .is_some_and(|old| !record_is_newer(record, old))
        {
            continue;
        }
        *selected = Some(Candidate {
            timestamp: record.timestamp.clone(),
            sequence: record.sequence,
            snapshot,
        });
    }
    Ok(())
}

fn record_is_newer(record: &SessionRecord, old: &Candidate) -> bool {
    (&record.timestamp, record.sequence) > (&old.timestamp, old.sequence)
}

fn conversation_event(
    record: &SessionRecord,
    target: &Path,
) -> Result<Option<Option<ConversationSnapshot>>> {
    match record.event_type.as_str() {
        "agent_conversation" => snapshot_event(record, target),
        "agent_conversation_cleared" => Ok(clears_target(record, target).then_some(None)),
        "truncated" => reject_truncated_conversation(record),
        _ => Ok(None),
    }
}

fn snapshot_event(
    record: &SessionRecord,
    target: &Path,
) -> Result<Option<Option<ConversationSnapshot>>> {
    let snapshot: ConversationSnapshot =
        serde_json::from_value(record.payload["snapshot"].clone())?;
    snapshot.validate()?;
    Ok((snapshot.context.canonical_target == target).then_some(Some(snapshot)))
}

fn clears_target(record: &SessionRecord, target: &Path) -> bool {
    record.payload["target"]
        .as_str()
        .is_some_and(|value| Path::new(value) == target)
}

fn reject_truncated_conversation(
    record: &SessionRecord,
) -> Result<Option<Option<ConversationSnapshot>>> {
    anyhow::ensure!(
        !matches!(
            record.payload["originalType"].as_str(),
            Some("agent_conversation" | "agent_conversation_cleared")
        ),
        "saved Ask history was truncated; recovery was not applied"
    );
    Ok(None)
}

#[cfg(test)]
mod tests;
