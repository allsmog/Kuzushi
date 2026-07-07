use super::*;
use crate::content_store::ContentStore;
use crate::identity::{compute_observation_hash_v3, hash_parts, ObservationHashInput};
use crate::storage_v3::writer_actor::{
    FileFactWrite, ObservationWrite, SnapshotWrite, StorageWriterActor, WatcherCommand,
    WriteReceipt, WriterCommand,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct FindingInsertOutcome {
    id: i64,
    projected: Finding,
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
        // Identity bookkeeping stays transactional while the mutable finding
        // view is projected by the v3 writer after the observation event is
        // appended. This keeps current finding state behind the event log.
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open findings write transaction")?;
        let outcome = self.insert_finding_statements(&tx, scan_id, finding)?;
        tx.commit()
            .context("Could not commit findings write transaction")?;
        self.record_v3_observation(scan_id, finding, outcome)
    }

    pub fn insert_findings(&self, scan_id: &str, findings: &[Finding]) -> Result<Vec<i64>> {
        findings
            .iter()
            .map(|finding| self.insert_finding(scan_id, finding))
            .collect()
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
        let id = projected_finding_id(scan_id, &finding.fingerprint);
        let projected = projected_seed(scan_id, id, finding, &identity);
        let evidence = self.verified_finding_evidence(tx, scan_id, &finding.evidence)?;
        Ok(FindingInsertOutcome {
            id,
            projected,
            evidence: ProjectionEvidence::Replace(evidence),
        })
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
        let evidence = self.collision_projection_evidence(tx, scan_id, &existing, finding)?;
        self.record_collision_identity(tx, &existing, finding)?;
        let identity = match collision_identity_assignment(&existing) {
            Some(identity) => identity,
            None => self.identity_assignment_for_finding(tx, scan_id, finding)?,
        };
        let projected = merged_projection_seed(
            scan_id,
            merge_id,
            existing,
            finding,
            &identity,
            &merged_tool,
            merged_source,
        );
        Ok(FindingInsertOutcome {
            id: merge_id,
            projected,
            evidence,
        })
    }

    fn collision_projection_evidence(
        &self,
        tx: &Connection,
        scan_id: &str,
        existing: &Finding,
        incoming: &Finding,
    ) -> Result<ProjectionEvidence> {
        if incoming.severity <= existing.severity {
            return Ok(ProjectionEvidence::KeepExisting);
        }
        Ok(ProjectionEvidence::Replace(self.verified_finding_evidence(
            tx,
            scan_id,
            &incoming.evidence,
        )?))
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
            "select finding_json
               from finding_current
              where run_id = ?1
                and dedup_key = ?2
                and not (run_id = ?1 and fingerprint = ?3)
              order by id asc
              limit 1",
        )?;
        let row = stmt
            .query_row(params![scan_id, dedup_key, new_fingerprint], row_to_current_finding)
            .optional()?;
        Ok(row)
    }

    fn record_v3_observation(
        &self,
        scan_id: &str,
        finding: &Finding,
        outcome: FindingInsertOutcome,
    ) -> Result<i64> {
        let commit = self.v3_observation_commit(scan_id, finding, outcome)?;
        self.commit_v3_observation(commit)
    }

    fn v3_observation_commit(
        &self,
        scan_id: &str,
        finding: &Finding,
        outcome: FindingInsertOutcome,
    ) -> Result<ObservationCommit> {
        let projected = self.projected_observation_finding(scan_id, finding, outcome)?;
        let provenance = self.observation_provenance(scan_id, &projected)?;
        let stable_fp = projected
            .identity_id
            .clone()
            .unwrap_or_else(|| projected.fingerprint.clone());
        let observation = observation_write(scan_id, &projected, stable_fp, &provenance)?;
        Ok(ObservationCommit {
            observation,
            provenance,
        })
    }

    fn projected_observation_finding(
        &self,
        scan_id: &str,
        finding: &Finding,
        outcome: FindingInsertOutcome,
    ) -> Result<Finding> {
        let mut projected = outcome.projected;
        projected.corroboration_count = projected.corroboration_count.max(1);
        let previous_projection = self.v3_finding_by_projected_id(outcome.id)?;
        carry_previous_triage(&mut projected, previous_projection.as_ref());
        let sources =
            self.projected_finding_sources(previous_projection.as_ref(), scan_id, finding);
        apply_projected_sources(&mut projected, sources);
        projected.evidence = projected_evidence(outcome.evidence, previous_projection.as_ref());
        Ok(projected)
    }

    fn commit_v3_observation(&self, commit: ObservationCommit) -> Result<i64> {
        let (event_log_dir, db_path) =
            self.required_v3_storage_paths("record finding observation")?;
        let receipts = StorageWriterActor::commit_blocking_many(
            event_log_dir,
            db_path,
            observation_commands(commit),
        )?;
        projected_finding_id_from_receipts(receipts)
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
    let snapshot_hash = observation_snapshot_hash_for(scan_id, provenance);
    let finding_json =
        serde_json::to_string(finding).context("Could not serialize v3 finding projection row")?;
    Ok(ObservationWrite {
        projected_finding_id: finding.id,
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
        blob_hash: observation_blob_hash(provenance),
        byte_start: observation_byte_start(provenance),
        byte_end: observation_byte_end(provenance),
        display_path: Some(finding.file_path.clone()),
        display_line: Some(finding.start_line),
        raw_result_hash,
        finding_json: Some(finding_json),
        actor: "finding-store".to_string(),
    })
}

fn observation_snapshot_hash_for(
    scan_id: &str,
    provenance: &Option<ObservationProvenance>,
) -> String {
    provenance
        .as_ref()
        .map(|provenance| provenance.snapshot.snapshot_hash.clone())
        .unwrap_or_else(|| run_snapshot_hash(scan_id))
}

fn observation_blob_hash(provenance: &Option<ObservationProvenance>) -> Option<String> {
    provenance
        .as_ref()
        .map(|provenance| provenance.blob_hash.clone())
}

fn observation_byte_start(provenance: &Option<ObservationProvenance>) -> Option<u64> {
    provenance
        .as_ref()
        .and_then(|provenance| provenance.byte_span)
        .map(|(start, _)| start)
}

fn observation_byte_end(provenance: &Option<ObservationProvenance>) -> Option<u64> {
    provenance
        .as_ref()
        .and_then(|provenance| provenance.byte_span)
        .map(|(_, end)| end)
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

fn projected_finding_id_from_receipts(receipts: Vec<WriteReceipt>) -> Result<i64> {
    receipts
        .into_iter()
        .rev()
        .find_map(|receipt| receipt.projected_finding_id)
        .context("finding observation did not project a finding id")
}

fn source_path_for_finding(root: &Path, file_path: &str) -> Option<PathBuf> {
    let path = Path::new(file_path);
    if path.is_absolute() {
        return path.starts_with(root).then(|| path.to_path_buf());
    }
    Some(root.join(path))
}

fn projected_seed(
    scan_id: &str,
    finding_id: i64,
    finding: &Finding,
    identity: &FindingIdentityAssignment,
) -> Finding {
    let mut projected = finding.clone();
    apply_projection_identity(&mut projected, scan_id, finding_id, identity);
    projected
}

fn projected_finding_id(scan_id: &str, fingerprint: &str) -> i64 {
    let hash = hash_parts(
        "finding-projected-id",
        &[scan_id.as_bytes(), fingerprint.as_bytes()],
    );
    let raw = u64::from_str_radix(&hash.as_str()[..16], 16).unwrap_or(1);
    ((raw & 0x7fff_ffff_ffff_ffff) as i64).max(1)
}

fn merged_projection_seed(
    scan_id: &str,
    finding_id: i64,
    existing: Finding,
    incoming: &Finding,
    identity: &FindingIdentityAssignment,
    merged_tool: &str,
    merged_source: Option<VulnSource>,
) -> Finding {
    let mut projected = if incoming.severity > existing.severity {
        incoming.clone()
    } else {
        existing
    };
    projected.tool = merged_tool.to_string();
    projected.vuln_source = merged_source;
    apply_projection_identity(&mut projected, scan_id, finding_id, identity);
    projected
}

fn apply_projection_identity(
    projected: &mut Finding,
    scan_id: &str,
    finding_id: i64,
    identity: &FindingIdentityAssignment,
) {
    projected.id = Some(finding_id);
    projected.scan_id = Some(scan_id.to_string());
    projected.identity_id = Some(identity.identity_id.clone());
    projected.identity_match_tier = Some(identity.match_tier.as_str().to_string());
}

fn row_to_current_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let raw: String = row.get(0)?;
    serde_json::from_str(&raw).map_err(|error| to_sql_error(anyhow::Error::new(error)))
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

fn collision_identity_assignment(finding: &Finding) -> Option<FindingIdentityAssignment> {
    Some(FindingIdentityAssignment {
        identity_id: finding.identity_id.clone()?,
        match_tier: identity_match_tier(finding.identity_match_tier.as_deref()),
    })
}

fn identity_match_tier(raw: Option<&str>) -> FindingIdentityMatchTier {
    match raw {
        Some("dedup_collision") => FindingIdentityMatchTier::DedupCollision,
        _ => FindingIdentityMatchTier::StableFingerprint,
    }
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
