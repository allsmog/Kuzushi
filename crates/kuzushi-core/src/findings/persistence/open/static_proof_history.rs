use super::*;

impl FindingStore {
    pub fn list_static_proof_history(&self, finding_id: i64) -> Result<Vec<StaticProofStateEvent>> {
        let Some(identity) = self.finding_identity_for_id(finding_id, "static proof history")?
        else {
            return Ok(Vec::new());
        };
        let mut stmt = self.conn.prepare(
            r#"
            select run_id, tool, finding_json, created_seq, created_at
              from finding_observations
             where stable_fp = ?1
               and finding_json is not null
             order by created_seq asc
            "#,
        )?;
        let rows = stmt.query_map(params![identity.stable_fp()], static_proof_observation_row)?;
        static_proof_history_from_observations(finding_id, rows)
    }
}

struct StaticProofObservation {
    run_id: String,
    tool: String,
    finding_json: String,
    created_seq: i64,
    created_at: String,
}

fn static_proof_observation_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StaticProofObservation> {
    Ok(StaticProofObservation {
        run_id: row.get(0)?,
        tool: row.get(1)?,
        finding_json: row.get(2)?,
        created_seq: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn static_proof_history_from_observations(
    finding_id: i64,
    rows: impl Iterator<Item = rusqlite::Result<StaticProofObservation>>,
) -> Result<Vec<StaticProofStateEvent>> {
    let mut history = Vec::new();
    let mut previous = None;
    for row in rows {
        let row = row?;
        let Some(next_state) = static_proof_state_from_json(&row.finding_json)? else {
            continue;
        };
        if previous == Some(next_state) {
            continue;
        }
        history.push(StaticProofStateEvent {
            id: row.created_seq,
            finding_id,
            scan_id: row.run_id,
            previous_state: previous,
            next_state,
            source: row.tool,
            created_at: row.created_at,
        });
        previous = Some(next_state);
    }
    Ok(history)
}

fn static_proof_state_from_json(raw: &str) -> Result<Option<StaticProofState>> {
    let finding: Finding =
        serde_json::from_str(raw).context("Could not parse v3 finding static proof history")?;
    Ok(finding.static_proof_state)
}
