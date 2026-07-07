use super::*;
use crate::content_store::ContentStore;
use crate::identity::{compute_observation_hash_v3, hash_parts, ObservationHashInput};
use crate::storage_v3::writer_actor::{
    FileFactWrite, ObservationWrite, SnapshotWrite, StorageWriterActor, WatcherCommand,
    WriterCommand,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct FindingInsertOutcome {
    id: i64,
    evidence: ProjectionEvidence,
}

struct ObservationCommit {
    observation: ObservationWrite,
    provenance: Option<ObservationProvenance>,
}

struct ObservationProvenance {
    snapshot: SnapshotWrite,
    file: FileFactWrite,
    blob_hash: String,
    byte_span: Option<(u64, u64)>,
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

    pub fn insert_findings(&self, scan_id: &str, findings: &[Finding]) -> Result<Vec<i64>> {
        if findings.is_empty() {
            return Ok(Vec::new());
        }

        let outcomes = self.insert_findings_transaction(scan_id, findings)?;
        let ids = outcomes.iter().map(|outcome| outcome.id).collect();
        self.record_v3_observations(scan_id, findings, outcomes)?;
        Ok(ids)
    }

    fn insert_findings_transaction(
        &self,
        scan_id: &str,
        findings: &[Finding],
    ) -> Result<Vec<FindingInsertOutcome>> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open findings write transaction")?;
        let outcomes = findings
            .iter()
            .map(|finding| self.insert_finding_statements(&tx, scan_id, finding))
            .collect::<Result<Vec<_>>>()?;
        tx.commit()
            .context("Could not commit findings write transaction")?;
        Ok(outcomes)
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
                if dedup_collision_can_merge(&existing, finding) {
                    return self.merge_finding_collision(tx, existing, scan_id, finding);
                }
            }
        }

        let identity = self.identity_assignment_for_finding(tx, scan_id, finding)?;
        self.upsert_finding(tx, scan_id, finding, &identity)?;
        let id: i64 = tx.query_row(
            "select id from finding_projection_rows where run_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
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
            "select id, run_id, fingerprint, rule_id, title, severity, file_path,
                    start_line, end_line, message, tool, vuln_source, source_signature,
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
        let Some(commit) = self.v3_observation_commit(scan_id, finding, finding_id, evidence)?
        else {
            return Ok(());
        };
        self.commit_v3_observation(commit)
    }

    fn record_v3_observations(
        &self,
        scan_id: &str,
        findings: &[Finding],
        outcomes: Vec<FindingInsertOutcome>,
    ) -> Result<()> {
        for (finding, outcome) in findings.iter().zip(outcomes) {
            self.record_v3_observation(scan_id, finding, outcome.id, outcome.evidence)?;
        }
        Ok(())
    }

    fn v3_observation_commit(
        &self,
        scan_id: &str,
        finding: &Finding,
        finding_id: i64,
        evidence: ProjectionEvidence,
    ) -> Result<Option<ObservationCommit>> {
        let Some(identity) = self.finding_identity_for_id(finding_id, "observation")? else {
            return Ok(None);
        };
        let projected =
            self.projected_observation_finding(scan_id, finding, finding_id, evidence)?;
        let provenance = self.observation_provenance(scan_id, &projected)?;
        let observation =
            observation_write(scan_id, &projected, identity.stable_fp(), &provenance)?;
        Ok(Some(ObservationCommit {
            observation,
            provenance,
        }))
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

    fn commit_v3_observation(&self, commit: ObservationCommit) -> Result<()> {
        let (event_log_dir, db_path) =
            self.required_v3_storage_paths("record finding observation")?;
        StorageWriterActor::commit_blocking_many(
            event_log_dir,
            db_path,
            observation_commands(commit),
        )?;
        Ok(())
    }

    fn observation_provenance(
        &self,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<Option<ObservationProvenance>> {
        let Some(root) = self.v3_workspace_root() else {
            return Ok(None);
        };
        let Some(source_path) = source_path_for_finding(&root, &finding.file_path) else {
            return Ok(None);
        };
        let Some(bytes) = read_optional_file(&source_path)? else {
            return Ok(None);
        };
        let Some(objects_dir) = self.v3_objects_dir() else {
            return Ok(None);
        };
        let store = ContentStore::open(objects_dir)?;
        let blob_ref = store.put_blob(&bytes)?;
        let byte_span = line_byte_span(&bytes, finding.start_line, finding.end_line);
        Ok(Some(build_observation_provenance(
            scan_id,
            &root,
            finding,
            &source_path,
            blob_ref.hash.as_str().to_string(),
            blob_ref.size_bytes,
            store.object_path(&blob_ref.hash),
            byte_span,
        )))
    }

    fn v3_workspace_root(&self) -> Option<PathBuf> {
        let v3_dir = self.db_path.as_ref()?.parent()?;
        let state_root = v3_dir.parent()?;
        if state_root.file_name()? != ".kuzushi" {
            return None;
        }
        Some(state_root.parent()?.to_path_buf())
    }

    fn v3_objects_dir(&self) -> Option<PathBuf> {
        Some(self.db_path.as_ref()?.parent()?.join("objects"))
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
}

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
    provenance: &Option<ObservationProvenance>,
) -> Result<ObservationWrite> {
    let raw_result_hash = raw_result_hash(scan_id, finding)?;
    let snapshot_hash = provenance
        .as_ref()
        .map(|provenance| provenance.snapshot.snapshot_hash.clone())
        .unwrap_or_else(|| run_snapshot_hash(scan_id));
    let finding_json =
        serde_json::to_string(finding).context("Could not serialize v3 finding projection row")?;
    let byte_span = provenance
        .as_ref()
        .and_then(|provenance| provenance.byte_span);
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
        blob_hash: provenance
            .as_ref()
            .map(|provenance| provenance.blob_hash.clone()),
        byte_start: byte_span.map(|(start, _)| start),
        byte_end: byte_span.map(|(_, end)| end),
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

fn run_snapshot_hash(scan_id: &str) -> String {
    format!(
        "snapshot_{}",
        hash_parts("run-snapshot", &[scan_id.as_bytes()]).as_str()
    )
}

fn observation_commands(commit: ObservationCommit) -> Vec<WriterCommand> {
    let mut commands = Vec::new();
    if let Some(provenance) = commit.provenance {
        commands.push(WriterCommand::Watcher(WatcherCommand::SnapshotIndexed(
            provenance.snapshot,
        )));
        commands.push(WriterCommand::Watcher(WatcherCommand::FileIndexed(
            provenance.file,
        )));
    }
    commands.push(WriterCommand::Watcher(WatcherCommand::FindingObservation(
        commit.observation,
    )));
    commands
}

fn source_path_for_finding(root: &Path, file_path: &str) -> Option<PathBuf> {
    let path = Path::new(file_path);
    if path.is_absolute() {
        return path.starts_with(root).then(|| path.to_path_buf());
    }
    Some(root.join(path))
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
    }
}

fn build_observation_provenance(
    scan_id: &str,
    root: &Path,
    finding: &Finding,
    source_path: &Path,
    blob_hash: String,
    file_size: u64,
    storage_path: PathBuf,
    byte_span: Option<(u64, u64)>,
) -> ObservationProvenance {
    let snapshot_hash = observation_snapshot_hash(scan_id, root, finding, &blob_hash);
    let tree_hash = observation_tree_hash(&finding.file_path, &blob_hash);
    ObservationProvenance {
        snapshot: observation_snapshot_write(root, snapshot_hash.clone(), tree_hash, &blob_hash),
        file: observation_file_fact_write(
            finding,
            source_path,
            snapshot_hash,
            &blob_hash,
            file_size,
            storage_path,
        ),
        blob_hash,
        byte_span,
    }
}

fn observation_snapshot_write(
    root: &Path,
    snapshot_hash: String,
    tree_hash: String,
    blob_hash: &str,
) -> SnapshotWrite {
    SnapshotWrite {
        snapshot_hash,
        tree_hash,
        workspace_root_fingerprint: workspace_root_fingerprint(root),
        git_commit: None,
        git_branch: None,
        dirty_hash: Some(blob_hash.to_string()),
        index_hash: None,
        config_hash: None,
        actor: "finding-store".to_string(),
    }
}

fn observation_file_fact_write(
    finding: &Finding,
    source_path: &Path,
    snapshot_hash: String,
    blob_hash: &str,
    file_size: u64,
    storage_path: PathBuf,
) -> FileFactWrite {
    FileFactWrite {
        snapshot_hash,
        path: finding.file_path.clone(),
        blob_hash: blob_hash.to_string(),
        storage_path: Some(storage_path.display().to_string()),
        file_size,
        mtime_ns: modified_ns(source_path),
        git_blob_oid: None,
        language: crate::workspace::inventory::language_for_path(source_path).map(str::to_string),
        ast_hash: None,
        actor: "finding-store".to_string(),
    }
}

fn observation_snapshot_hash(
    scan_id: &str,
    root: &Path,
    finding: &Finding,
    blob_hash: &str,
) -> String {
    format!(
        "snapshot_{}",
        hash_parts(
            "finding-observation-snapshot",
            &[
                scan_id.as_bytes(),
                root.to_string_lossy().as_bytes(),
                finding.file_path.as_bytes(),
                blob_hash.as_bytes(),
            ],
        )
        .as_str()
    )
}

fn observation_tree_hash(path: &str, blob_hash: &str) -> String {
    hash_parts(
        "finding-observation-tree",
        &[path.as_bytes(), blob_hash.as_bytes()],
    )
    .as_str()
    .to_string()
}

fn workspace_root_fingerprint(root: &Path) -> String {
    hash_parts("workspace-root", &[root.to_string_lossy().as_bytes()])
        .as_str()
        .to_string()
}

fn modified_ns(path: &Path) -> Option<i64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    system_time_ns(modified)
}

fn system_time_ns(value: SystemTime) -> Option<i64> {
    let duration = value.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_nanos()).ok()
}

fn line_byte_span(bytes: &[u8], start_line: u32, end_line: Option<u32>) -> Option<(u64, u64)> {
    if start_line == 0 {
        return None;
    }
    let end_line = end_line.unwrap_or(start_line).max(start_line);
    let start = line_start(bytes, start_line)?;
    let end = line_end(bytes, end_line)?;
    Some((start as u64, end as u64))
}

fn line_start(bytes: &[u8], target_line: u32) -> Option<usize> {
    let mut line = 1;
    let mut offset = 0;
    while line < target_line {
        let next = bytes[offset..].iter().position(|byte| *byte == b'\n')?;
        offset += next + 1;
        line += 1;
    }
    (offset <= bytes.len()).then_some(offset)
}

fn line_end(bytes: &[u8], target_line: u32) -> Option<usize> {
    let start = line_start(bytes, target_line)?;
    let relative_end = bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len() - start);
    Some(start + relative_end)
}

struct CollisionRow {
    id: i64,
    scan_id: String,
    fingerprint: String,
    rule_id: String,
    title: String,
    severity: String,
    file_path: String,
    start_line: i64,
    end_line: Option<i64>,
    message: String,
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
            rule_id: self.rule_id,
            title: self.title,
            severity: Severity::try_from(self.severity.as_str()).unwrap_or(Severity::Unknown),
            file_path: self.file_path,
            start_line: self.start_line.max(1) as u32,
            end_line: self.end_line.map(|line| line.max(1) as u32),
            message: self.message,
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
        rule_id: row.get(3)?,
        title: row.get(4)?,
        severity: row.get(5)?,
        file_path: row.get(6)?,
        start_line: row.get(7)?,
        end_line: row.get(8)?,
        message: row.get(9)?,
        tool: row.get(10)?,
        vuln_source: row.get(11)?,
        source_signature: row.get(12)?,
        corroboration_count: row.get(13)?,
        identity_id: row.get(14)?,
        identity_match_tier: row.get(15)?,
    })
}

fn dedup_collision_can_merge(existing: &Finding, incoming: &Finding) -> bool {
    match (
        existing.source_signature.as_deref(),
        incoming.source_signature.as_deref(),
    ) {
        (Some(left), Some(right)) => return left == right,
        (Some(_), None) | (None, Some(_)) => return false,
        (None, None) => {}
    }
    existing.rule_id == incoming.rule_id
        && normalized_collision_text(&existing.message)
            == normalized_collision_text(&incoming.message)
}

fn normalized_collision_text(value: &str) -> String {
    crate::identity::finding_identity::normalize_finding_text(value)
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
