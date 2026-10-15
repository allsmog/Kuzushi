//! Exact decision source metadata, projected from its original event payload.
use super::*;

impl FindingStore {
    pub fn reviewed_source_for_decision(
        &self,
        decision_id: i64,
    ) -> Result<Option<crate::findings::ReviewSourceCapture>> {
        let value: Option<Option<String>> = self
            .conn
            .query_row(
                "select json_extract(events.payload_json, '$.reviewedSource')
             from review_decisions decisions join finding_events events
             on events.seq = decisions.decision_event_seq
             and events.event_hash = decisions.decision_event_hash
             where decisions.id = ?1",
                params![decision_id],
                |row| row.get(0),
            )
            .optional()
            .context("Could not read reviewed source for the saved decision")?;
        value
            .flatten()
            .map(|value| {
                serde_json::from_str(&value).context("Recorded reviewed source is malformed")
            })
            .transpose()
    }
}
