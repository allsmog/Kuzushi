use super::*;

impl FindingStore {
    pub fn list_static_proof_history(
        &self,
        finding_id: i64,
    ) -> Result<Vec<StaticProofStateEvent>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, scan_id, previous_state, next_state, source, created_at
              from static_proof_history
             where finding_id = ?1
             order by created_at asc, id asc
            "#,
        )?;
        let rows = stmt.query_map(params![finding_id], static_proof_state_event_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list static proof state events")
    }

    pub(in crate::findings::persistence::open) fn append_static_proof_state_event(
        &self,
        tx: &Connection,
        finding_id: i64,
        scan_id: &str,
        previous_state: Option<StaticProofState>,
        next_state: StaticProofState,
        source: &str,
        created_at: &str,
    ) -> Result<()> {
        tx.execute(
            r#"
            insert into static_proof_history(
              finding_id, scan_id, previous_state, next_state, source, created_at
            )
            values (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                finding_id,
                scan_id,
                previous_state.map(StaticProofState::as_str),
                next_state.as_str(),
                source,
                created_at,
            ],
        )?;
        Ok(())
    }
}

fn static_proof_state_event_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StaticProofStateEvent> {
    let previous_state: Option<String> = row.get(3)?;
    let next_state: String = row.get(4)?;
    Ok(StaticProofStateEvent {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        scan_id: row.get(2)?,
        previous_state: previous_state
            .as_deref()
            .map(StaticProofState::try_from)
            .transpose()
            .map_err(to_sql_error)?,
        next_state: StaticProofState::try_from(next_state.as_str()).map_err(to_sql_error)?,
        source: row.get(5)?,
        created_at: row.get(6)?,
    })
}
