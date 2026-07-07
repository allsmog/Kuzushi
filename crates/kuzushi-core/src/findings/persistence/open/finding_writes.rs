use super::*;
use crate::identity::{compute_observation_hash_v3, hash_parts, ObservationHashInput};
use crate::storage_v3::writer_actor::{
    ObservationWrite, StorageWriterActor, WatcherCommand, WriterCommand,
};

struct FindingInsertOutcome {
    id: i64,
    evidence: ProjectionEvidence,
}

enum ProjectionEvidence {
    Replace(Vec<FindingEvidence>),
    KeepExisting,
}

impl FindingStore {
    pub fn insert_finding(&self, scan_id: &str, finding: &Finding) -> Result<i64> {
        // The collision-check → upsert → source/identity → projection
        // sequence must commit as one unit: a crash or error partway through
        // must never leave a header row without its dependent source rows.
        //
        // We open one transaction and thread its connection handle (`tx`)
        // through every write below, so participation in the transaction is
        // explicit at each call site rather than relying on ambient
        // connection state. `unchecked_transaction` is required because the
        // store is reached behind `&self`; the returned guard still rolls back
        // on drop and only persists on the explicit `commit()`.
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open findings write transaction")?;
        let outcome = self.insert_finding_statements(&tx, scan_id, finding)?;
        tx.commit()
            .context("Could not commit findings write transaction")?;
        self.record_v3_observation(scan_id, finding, outcome.id, outcome.evidence)?;
        Ok(outcome.id)
    }

    fn insert_finding_statements(
        &self,
        tx: &Connection,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<FindingInsertOutcome> {
        // Cross-channel dedup is scoped to one scan run. A rediscovered
        // vulnerability in a later run must still get its own row under that
        // run's scan_id so per-run summaries and --fail-on gates see it.
        if let Some(dedup_key) = finding.dedup_key.as_deref() {
            if let Some(existing) =
                self.find_collision(tx, scan_id, dedup_key, &finding.fingerprint)?
            {
                return self.merge_finding_collision(tx, existing, scan_id, finding);
            }
        }

        let identity = self.identity_assignment_for_finding(tx, scan_id, finding)?;
        let previous_static_proof_state =
            self.existing_static_proof_state(tx, scan_id, &finding.fingerprint)?;
        self.upsert_finding(tx, scan_id, finding, &identity)?;
        let id: i64 = tx.query_row(
            "select id from finding_projection_rows where run_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        self.record_static_proof_state_change(
            tx,
            scan_id,
            id,
            finding,
            previous_static_proof_state,
        )?;
        let evidence = self.verified_finding_evidence(tx, scan_id, &finding.evidence)?;
        Ok(FindingInsertOutcome {
            id,
            evidence: ProjectionEvidence::Replace(evidence),
        })
    }

    fn upsert_finding(
        &self,
        tx: &Connection,
        scan_id: &str,
        finding: &Finding,
        identity: &FindingIdentityAssignment,
    ) -> Result<()> {
        let references_json = references_json(&finding.references)?;
        tx.execute(
            UPSERT_FINDING_SQL,
            params![
                scan_id,
                finding.fingerprint,
                finding.rule_id,
                finding.title,
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.end_line,
                finding.message,
                finding.tool,
                finding.actor_fingerprint,
                finding.static_proof_state.map(StaticProofState::as_str),
                finding.created_at,
                finding.vuln_source.map(|s| s.as_str()),
                finding.dedup_key,
                finding.source_signature,
                finding.corroboration_count.max(1),
                finding.suppressed,
                finding.snoozed_until,
                finding.remediation,
                references_json,
                identity.identity_id,
                identity.match_tier.as_str(),
            ],
        )?;
        Ok(())
    }

    fn merge_finding_collision(
        &self,
        tx: &Connection,
        existing: Finding,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<FindingInsertOutcome> {
        let merge_id = existing.id.expect("existing finding always has id");
        let merged_tool = merge_tool_list(&existing.tool, &finding.tool);
        let merged_source = merge_vuln_source(existing.vuln_source, finding.vuln_source);
        let evidence = if finding.severity > existing.severity {
            self.replace_collision_headline(tx, merge_id, finding, &merged_tool, merged_source)?;
            ProjectionEvidence::Replace(self.verified_finding_evidence(
                tx,
                scan_id,
                &finding.evidence,
            )?)
        } else if existing.tool != merged_tool {
            self.update_collision_tool(tx, merge_id, &merged_tool, merged_source)?;
            ProjectionEvidence::KeepExisting
        } else {
            ProjectionEvidence::KeepExisting
        };
        self.record_collision_identity(tx, &existing, finding)?;
        Ok(FindingInsertOutcome {
            id: merge_id,
            evidence,
        })
    }

    fn replace_collision_headline(
        &self,
        tx: &Connection,
        id: i64,
        finding: &Finding,
        merged_tool: &str,
        merged_source: Option<VulnSource>,
    ) -> Result<()> {
        tx.execute(
            r#"update finding_projection_rows set
                 severity = ?, rule_id = ?, title = ?, message = ?,
                 tool = ?, vuln_source = ?, suppressed = ?,
                 snoozed_until = ?, remediation = ?, references_json = ?
               where id = ?"#,
            params![
                finding.severity.as_str(),
                finding.rule_id,
                finding.title,
                finding.message,
                merged_tool,
                merged_source.map(|s| s.as_str()),
                finding.suppressed,
                finding.snoozed_until,
                finding.remediation,
                references_json(&finding.references)?,
                id,
            ],
        )?;
        Ok(())
    }

    fn update_collision_tool(
        &self,
        tx: &Connection,
        id: i64,
        merged_tool: &str,
        merged_source: Option<VulnSource>,
    ) -> Result<()> {
        tx.execute(
            "update finding_projection_rows set tool = ?, vuln_source = ? where id = ?",
            params![merged_tool, merged_source.map(|s| s.as_str()), id],
        )?;
        Ok(())
    }

    fn existing_static_proof_state(
        &self,
        tx: &Connection,
        scan_id: &str,
        fingerprint: &str,
    ) -> Result<Option<StaticProofState>> {
        let raw = tx
            .query_row(
                "select static_proof_state from finding_projection_rows where run_id = ?1 and fingerprint = ?2",
                params![scan_id, fingerprint],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        raw.as_deref()
            .map(StaticProofState::try_from)
            .transpose()
            .context("Could not parse stored static proof state")
    }

    fn record_static_proof_state_change(
        &self,
        tx: &Connection,
        scan_id: &str,
        finding_id: i64,
        finding: &Finding,
        previous_state: Option<StaticProofState>,
    ) -> Result<()> {
        let Some(next_state) = finding.static_proof_state else {
            return Ok(());
        };
        if previous_state == Some(next_state) {
            return Ok(());
        }
        let created_at = static_proof_event_created_at(finding);
        self.append_static_proof_state_event(
            tx,
            finding_id,
            scan_id,
            previous_state,
            next_state,
            &finding.tool,
            &created_at,
        )
    }

    /// Look up an existing finding in this scan run that shares the dedup_key.
    /// Historical rows are intentionally ignored so each run keeps its own
    /// blocking-finding rows for CI and per-run reporting. Runs on the caller's
    /// transaction handle so the read sees this transaction's own writes.
    pub(crate) fn find_collision(
        &self,
        tx: &Connection,
        scan_id: &str,
        dedup_key: &str,
        new_fingerprint: &str,
    ) -> Result<Option<Finding>> {
        let mut stmt = tx.prepare(
            "select id, run_id, fingerprint, severity, tool, vuln_source, source_signature,
                    corroboration_count, identity_id, identity_match_tier
               from finding_projection_rows
              where run_id = ?1
                and dedup_key = ?2
                and not (run_id = ?1 and fingerprint = ?3)
              order by id asc
              limit 1",
        )?;
        let row = stmt
            .query_row(params![scan_id, dedup_key, new_fingerprint], collision_row)
            .optional()?;
        Ok(row.map(|row| row.into_finding(dedup_key)))
    }

    fn record_v3_observation(
        &self,
        scan_id: &str,
        finding: &Finding,
        finding_id: i64,
        evidence: ProjectionEvidence,
    ) -> Result<()> {
        let Some(write) = self.v3_observation_write(scan_id, finding, finding_id, evidence)? else {
            return Ok(());
        };
        self.commit_v3_observation_write(write)
    }

    fn v3_observation_write(
        &self,
        scan_id: &str,
        finding: &Finding,
        finding_id: i64,
        evidence: ProjectionEvidence,
    ) -> Result<Option<ObservationWrite>> {
        let Some(identity) = self.finding_identity_for_id(finding_id, "observation")? else {
            return Ok(None);
        };
        let projected =
            self.projected_observation_finding(scan_id, finding, finding_id, evidence)?;
        Ok(Some(observation_write(
            scan_id,
            &projected,
            identity.stable_fp(),
        )?))
    }

    fn projected_observation_finding(
        &self,
        scan_id: &str,
        finding: &Finding,
        finding_id: i64,
        evidence: ProjectionEvidence,
    ) -> Result<Finding> {
        let mut projected = self.projected_finding_for_v3(finding_id)?;
        let previous_projection = self.v3_finding_by_projected_id(finding_id)?;
        carry_previous_triage(&mut projected, previous_projection.as_ref());
        let sources =
            self.projected_finding_sources(previous_projection.as_ref(), scan_id, finding);
        apply_projected_sources(&mut projected, sources);
        projected.evidence = projected_evidence(evidence, previous_projection.as_ref());
        Ok(projected)
    }

    fn commit_v3_observation_write(&self, write: ObservationWrite) -> Result<()> {
        if let Some((event_log_dir, db_path)) = self.v3_storage_paths() {
            StorageWriterActor::commit_blocking(
                event_log_dir,
                db_path,
                WriterCommand::Watcher(WatcherCommand::FindingObservation(write)),
            )?;
        } else {
            self.insert_v3_observation_projection_direct(&write)?;
        }
        Ok(())
    }

    pub(crate) fn projected_finding_for_v3(&self, finding_id: i64) -> Result<Finding> {
        let finding = self
            .conn
            .query_row(
                r#"
                select
                  f.id, f.run_id, f.fingerprint, f.rule_id, f.title, f.severity,
                  f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
                  f.static_proof_state, f.created_at,
                  null, null, null, null,
                  f.vuln_source, f.dedup_key, f.suppressed, f.snoozed_until,
                  f.remediation, f.references_json, null, f.source_signature,
                  f.corroboration_count, f.identity_id, f.identity_match_tier
                from finding_projection_rows f
                where f.id = ?1
                "#,
                params![finding_id],
                row_to_finding,
            )
            .with_context(|| format!("Could not load finding {finding_id} for v3 projection"))?;
        Ok(finding)
    }

    fn insert_v3_observation_projection_direct(&self, write: &ObservationWrite) -> Result<()> {
        let created_seq = self.next_in_memory_projection_seq()?;
        self.conn.execute(
            UPSERT_V3_OBSERVATION_PROJECTION_SQL,
            params![
                write.observation_hash,
                write.stable_fp,
                write.snapshot_hash,
                write.run_id,
                write.tool,
                write.tool_version,
                write.rule_id,
                write.rule_set_hash,
                write.severity,
                write.title,
                write.message,
                write.blob_hash,
                write.byte_start.map(|value| value as i64),
                write.byte_end.map(|value| value as i64),
                write.display_path,
                write.display_line.map(i64::from),
                write.raw_result_hash,
                write.finding_json,
                created_seq,
                now_isoish(),
            ],
        )?;
        Ok(())
    }

    fn next_in_memory_projection_seq(&self) -> Result<i64> {
        self.conn
            .query_row(
                "select coalesce(max(created_seq), 0) + 1 from finding_observations",
                [],
                |row| row.get(0),
            )
            .context("Could not allocate in-memory v3 projection sequence")
    }
}

const UPSERT_V3_OBSERVATION_PROJECTION_SQL: &str = r#"
insert into finding_observations(
  observation_hash, stable_fp, snapshot_hash, run_id, tool, tool_version,
  rule_id, rule_set_hash, severity, title, message, blob_hash, byte_start,
  byte_end, display_path, display_line, raw_result_hash, finding_json,
  created_seq, created_at
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
on conflict(observation_hash) do update set
  severity = excluded.severity,
  title = excluded.title,
  message = excluded.message,
  finding_json = excluded.finding_json,
  created_seq = excluded.created_seq,
  created_at = excluded.created_at
"#;

fn carry_previous_triage(projected: &mut Finding, previous: Option<&Finding>) {
    if projected.triage.is_some() {
        return;
    }
    let Some(previous) = previous else {
        return;
    };
    projected.triage = previous.triage.clone();
    projected.triaged_by = previous.triaged_by;
}

fn apply_projected_sources(projected: &mut Finding, sources: Vec<FindingSource>) {
    projected.sources = sources;
    if projected.sources.is_empty() {
        return;
    }
    projected.corroboration_count = projected.sources.len() as u32;
    if projected.source_signature.is_none() {
        projected.source_signature = first_source_signature(&projected.sources);
    }
}

fn first_source_signature(sources: &[FindingSource]) -> Option<String> {
    sources
        .first()
        .map(|source| source.source_signature.clone())
}

fn projected_evidence(
    evidence: ProjectionEvidence,
    previous_projection: Option<&Finding>,
) -> Vec<FindingEvidence> {
    match evidence {
        ProjectionEvidence::Replace(evidence) => evidence,
        ProjectionEvidence::KeepExisting => previous_projection
            .map(|finding| finding.evidence.clone())
            .unwrap_or_default(),
    }
}

fn observation_write(
    scan_id: &str,
    finding: &Finding,
    stable_fp: String,
) -> Result<ObservationWrite> {
    let raw_result_hash = raw_result_hash(scan_id, finding)?;
    let snapshot_hash = legacy_scan_snapshot_hash(scan_id);
    let finding_json =
        serde_json::to_string(finding).context("Could not serialize v3 finding projection row")?;
    Ok(ObservationWrite {
        observation_hash: observation_hash(scan_id, finding, &snapshot_hash, &raw_result_hash),
        stable_fp,
        snapshot_hash,
        run_id: scan_id.to_string(),
        tool: finding.tool.clone(),
        tool_version: None,
        rule_id: finding.rule_id.clone(),
        rule_set_hash: None,
        severity: finding.severity.as_str().to_string(),
        title: finding.title.clone(),
        message: finding.message.clone(),
        blob_hash: None,
        byte_start: None,
        byte_end: None,
        display_path: Some(finding.file_path.clone()),
        display_line: Some(finding.start_line),
        raw_result_hash,
        finding_json: Some(finding_json),
        actor: "finding-store".to_string(),
    })
}

fn observation_hash(
    scan_id: &str,
    finding: &Finding,
    snapshot_hash: &str,
    raw_result_hash: &str,
) -> String {
    compute_observation_hash_v3(ObservationHashInput {
        run_id: scan_id,
        tool_name: &finding.tool,
        tool_version: None,
        rule_set_hash: None,
        snapshot_hash: Some(snapshot_hash),
        raw_result_hash,
    })
}

fn static_proof_event_created_at(finding: &Finding) -> String {
    if finding.created_at.trim().is_empty() {
        now_isoish()
    } else {
        finding.created_at.clone()
    }
}

fn raw_result_hash(scan_id: &str, finding: &Finding) -> Result<String> {
    let raw = serde_json::to_vec(&serde_json::json!({
        "scanId": scan_id,
        "finding": finding,
    }))
    .context("Could not serialize finding observation payload")?;
    Ok(hash_parts("finding-raw-result", &[&raw])
        .as_str()
        .to_string())
}

fn legacy_scan_snapshot_hash(scan_id: &str) -> String {
    format!(
        "snapshot_{}",
        hash_parts("legacy-scan-snapshot", &[scan_id.as_bytes()]).as_str()
    )
}

struct CollisionRow {
    id: i64,
    scan_id: String,
    fingerprint: String,
    severity: String,
    tool: String,
    vuln_source: Option<String>,
    source_signature: Option<String>,
    corroboration_count: i64,
    identity_id: Option<String>,
    identity_match_tier: Option<String>,
}

impl CollisionRow {
    fn into_finding(self, dedup_key: &str) -> Finding {
        Finding {
            id: Some(self.id),
            scan_id: Some(self.scan_id),
            fingerprint: self.fingerprint,
            severity: Severity::try_from(self.severity.as_str()).unwrap_or(Severity::Unknown),
            tool: self.tool,
            vuln_source: self.vuln_source.as_deref().and_then(VulnSource::parse),
            dedup_key: Some(dedup_key.to_string()),
            source_signature: self.source_signature,
            corroboration_count: self.corroboration_count.max(0) as u32,
            identity_id: self.identity_id,
            identity_match_tier: self.identity_match_tier,
            ..Finding::default()
        }
    }
}

fn collision_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CollisionRow> {
    Ok(CollisionRow {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        severity: row.get(3)?,
        tool: row.get(4)?,
        vuln_source: row.get(5)?,
        source_signature: row.get(6)?,
        corroboration_count: row.get(7)?,
        identity_id: row.get(8)?,
        identity_match_tier: row.get(9)?,
    })
}

fn references_json(references: &[String]) -> Result<Option<String>> {
    if references.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string(references)?))
}

const UPSERT_FINDING_SQL: &str = r#"
insert into finding_projection_rows(
  run_id, fingerprint, rule_id, title, severity, file_path,
  start_line, end_line, message, tool, actor_fingerprint,
  static_proof_state, created_at, vuln_source, dedup_key,
  source_signature, corroboration_count, suppressed, snoozed_until,
  remediation, references_json, identity_id, identity_match_tier
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
        ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)
on conflict(run_id, fingerprint) do update set
  title = excluded.title,
  severity = excluded.severity,
  message = excluded.message,
  actor_fingerprint = excluded.actor_fingerprint,
  static_proof_state = coalesce(excluded.static_proof_state, finding_projection_rows.static_proof_state),
  vuln_source = coalesce(excluded.vuln_source, finding_projection_rows.vuln_source),
  dedup_key = coalesce(excluded.dedup_key, finding_projection_rows.dedup_key),
  source_signature = coalesce(excluded.source_signature, finding_projection_rows.source_signature),
  corroboration_count = max(finding_projection_rows.corroboration_count, excluded.corroboration_count),
  suppressed = excluded.suppressed,
  snoozed_until = excluded.snoozed_until,
  remediation = excluded.remediation,
  references_json = excluded.references_json,
  identity_id = coalesce(excluded.identity_id, finding_projection_rows.identity_id),
  identity_match_tier = coalesce(excluded.identity_match_tier, finding_projection_rows.identity_match_tier)
"#;
