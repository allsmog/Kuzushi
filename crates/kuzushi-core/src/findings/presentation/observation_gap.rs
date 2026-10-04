use crate::findings::Finding;

/// A presence receipt never substitutes for a revision-specific verdict.
pub fn observation_gap_note(finding: &Finding) -> Option<String> {
    let gap = finding.observation_gap.as_ref()?;
    Some(format!(
        "Not observed in run {}; last observed in run {}. Absence does not establish a fix. Compare source revisions and coverage before reassessment.",
        gap.compared_run_id.as_deref().unwrap_or("not recorded"),
        gap.last_seen_run_id.as_deref().unwrap_or("not recorded"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingObservationGap;

    #[test]
    fn observation_gap_does_not_invent_missing_run_references() {
        let finding = Finding {
            observation_gap: Some(FindingObservationGap {
                event_seq: 1,
                event_hash: "legacy-event".to_string(),
                last_seen_run_id: None,
                compared_run_id: None,
            }),
            ..Finding::default()
        };
        let note = observation_gap_note(&finding).unwrap();
        assert!(note.contains("run not recorded"));
        assert!(note.contains("Absence does not establish a fix."));
    }

    #[test]
    fn legacy_finding_json_has_no_observation_gap() {
        let value = serde_json::to_value(Finding::default()).unwrap();
        assert!(value.get("observationGap").is_none());
        let finding: Finding = serde_json::from_value(value).unwrap();
        assert!(observation_gap_note(&finding).is_none());
    }
}
