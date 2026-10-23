//! Bounded journal groups keep their original envelopes and one durable sync.
use super::*;

pub(crate) const MAX_APPEND_BATCH_EVENTS: usize = 128;

pub(crate) struct EventAppend {
    pub kind: EventKind,
    pub actor: String,
    pub payload: Value,
}

impl EventLog {
    pub(crate) fn append_batch(&self, records: Vec<EventAppend>) -> Result<Vec<EventEnvelope>> {
        self.append_batch_with_sync(records, sync_directory)
    }

    fn append_batch_with_sync(
        &self,
        records: Vec<EventAppend>,
        sync: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<Vec<EventEnvelope>> {
        anyhow::ensure!(
            records.len() <= MAX_APPEND_BATCH_EVENTS,
            "Journal batch exceeds {MAX_APPEND_BATCH_EVENTS} events"
        );
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let events = prepare_envelopes(self.head()?, records)?;
        let bytes = encode_events(&events)?;
        let path = self.segment_path_for_append(bytes.len() as u64)?;
        let (mut file, created) = open_segment_for_append(&path)?;
        heal_torn_tail(&mut file, &path)?;
        *self.head.borrow_mut() = None;
        file.write_all(&bytes)
            .context("Could not append source-index journal batch")?;
        file.sync_all()
            .context("Could not sync source-index journal batch")?;
        if created {
            sync(&self.root)?;
        }
        *self.head.borrow_mut() = Some(events.last().cloned());
        Ok(events)
    }
}

fn prepare_envelopes(
    mut head: Option<EventEnvelope>,
    records: Vec<EventAppend>,
) -> Result<Vec<EventEnvelope>> {
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let seq = head
            .as_ref()
            .map_or(0, |row| row.seq)
            .checked_add(1)
            .context("Journal sequence overflow")?;
        anyhow::ensure!(
            seq <= MAX_EVENT_LOG_EVENTS as u64,
            "Journal exceeds the {MAX_EVENT_LOG_EVENTS}-event aggregate limit"
        );
        let previous = head.as_ref().map(|row| row.event_hash.clone());
        let event = envelope(seq, previous, record)?;
        head = Some(event.clone());
        events.push(event);
    }
    Ok(events)
}

fn envelope(seq: u64, previous: Option<Blake3Hash>, record: EventAppend) -> Result<EventEnvelope> {
    let created_at = now_isoish();
    let hash = event_hash(
        seq,
        previous.as_ref(),
        record.kind,
        &record.actor,
        None,
        None,
        &created_at,
        &record.payload,
    )?;
    Ok(EventEnvelope {
        seq,
        event_hash: hash,
        prev_event_hash: previous,
        event_kind: record.kind,
        actor: record.actor,
        run_id: None,
        target_snapshot: None,
        created_at,
        payload: record.payload,
    })
}

fn encode_events(events: &[EventEnvelope]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for event in events {
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        anyhow::ensure!(
            line.len() <= MAX_EVENT_LOG_LINE_BYTES,
            "Event log entry exceeds the {MAX_EVENT_LOG_LINE_BYTES}-byte line limit"
        );
        anyhow::ensure!(
            bytes.len().saturating_add(line.len()) <= MAX_EVENT_LOG_SEGMENT_BYTES as usize,
            "Journal batch exceeds one segment's byte limit"
        );
        bytes.extend(line);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
