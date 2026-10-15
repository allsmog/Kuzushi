use super::*;
use crate::findings::ReviewCapturedFileState;

pub(super) fn save(root: &Path, document: &ReviewSourceEvidence) -> Result<String> {
    let workspace = WorkspaceTarget::new(root)?;
    let object =
        ContentStore::open(workspace.objects_dir())?.put_json(ObjectKind::Blob, document)?;
    Ok(format!("{REFERENCE_PREFIX}{}", object.hash))
}

pub(crate) fn inspect(
    root: &Path,
    input: &Value,
    findings: &[Finding],
) -> Result<Option<ReviewSourceEvidence>> {
    if !validate_policy(input)? {
        return Ok(None);
    }
    let Some(reference) = input.get("sourceEvidenceRef") else {
        return Ok(None);
    };
    let reference = reference
        .as_str()
        .context("sourceEvidenceRef must be a saved reference")?;
    let workspace = WorkspaceTarget::new(root)?;
    let document = read(&workspace, reference)?;
    validate_document(&workspace, &document, findings, input)?;
    Ok(Some(document))
}

fn read(workspace: &WorkspaceTarget, reference: &str) -> Result<ReviewSourceEvidence> {
    let hash = crate::identity::Blake3Hash::new(
        reference
            .strip_prefix(REFERENCE_PREFIX)
            .context("Expected a frozen Review source-evidence reference")?
            .into(),
    )?;
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_blob_bounded(&hash, 16 * 1024 * 1024)?
        .context("Frozen Review source evidence is missing or exceeds its read limit")?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_document(
    workspace: &WorkspaceTarget,
    document: &ReviewSourceEvidence,
    findings: &[Finding],
    input: &Value,
) -> Result<()> {
    let supporting = supporting_files::selected_paths(input)?;
    validate_header(workspace, document, byte_limit(input)?)?;
    anyhow::ensure!(
        document.schema_version == if supporting.is_empty() { 1 } else { 2 },
        "Review source-evidence version does not match the selected files"
    );
    validate_snapshot(workspace, document)?;
    anyhow::ensure!(
        (1..=100).contains(&findings.len()) && document.observations.len() == findings.len(),
        "Review source-evidence selection changed"
    );
    let mut included = 0;
    let tree = crate::workspace::ReviewSourceTree::load(workspace, &document.tree_hash)?;
    let mut recorded = RecordedSources::new(workspace);
    for (source, finding) in document.observations.iter().zip(findings) {
        validate_observation(
            workspace,
            &document.tree_hash,
            &tree,
            &mut recorded,
            source,
            finding,
        )?;
        included += source.text.as_ref().map_or(0, String::len);
        included += supporting_files::validate(workspace, finding, &tree, source, &supporting)?;
    }
    anyhow::ensure!(
        included == document.included_bytes,
        "Review source-evidence byte receipt changed"
    );
    Ok(())
}

fn validate_header(
    workspace: &WorkspaceTarget,
    document: &ReviewSourceEvidence,
    limit: usize,
) -> Result<()> {
    anyhow::ensure!(
        matches!(document.schema_version, 1 | 2),
        "Unsupported Review source-evidence version"
    );
    anyhow::ensure!(
        document.target == workspace.root().canonicalize()?.to_string_lossy(),
        "Review source evidence belongs to another target"
    );
    anyhow::ensure!(
        document.max_bytes == limit && document.included_bytes <= limit,
        "Review source-evidence allowance changed"
    );
    Ok(())
}

fn validate_observation(
    workspace: &WorkspaceTarget,
    tree: &str,
    files: &crate::workspace::ReviewSourceTree,
    recorded: &mut RecordedSources<'_>,
    source: &ReviewSourceObservation,
    finding: &Finding,
) -> Result<()> {
    anyhow::ensure!(
        Some(source.generation_id) == finding.id,
        "Review source evidence belongs to another finding generation"
    );
    if let Some(file) = &source.file {
        anyhow::ensure!(
            file.path == source.path,
            "Review source-evidence path changed"
        );
        anyhow::ensure!(
            source.path == relative_finding_path(workspace, finding)?,
            "Review code does not belong to the selected primary source file"
        );
        validate_captured_file(files, file, source.text.as_deref())?;
    } else {
        anyhow::ensure!(
            source.text.is_none() && source.path == finding.file_path,
            "Review code has no matching cited-file receipt"
        );
    }
    validate_binding(recorded, tree, source, finding)
}

fn validate_binding(
    recorded: &mut RecordedSources<'_>,
    tree: &str,
    source: &ReviewSourceObservation,
    finding: &Finding,
) -> Result<()> {
    let expected = match source.binding {
        ReviewSourceBinding::ByteLimitReached => ReviewSourceBinding::MatchingRecordedSnapshot,
        binding => binding,
    };
    anyhow::ensure!(
        recorded.binding(finding, tree) == expected,
        "Recorded observation source no longer authenticates this evidence"
    );
    if source.binding == ReviewSourceBinding::MatchingRecordedSnapshot {
        anyhow::ensure!(
            source.file.is_some(),
            "Matching source evidence has no file receipt"
        );
        return Ok(());
    }
    anyhow::ensure!(
        source.text.is_none() && source.file.is_none(),
        "Unverified observation source cannot supply code"
    );
    Ok(())
}

pub(super) fn validate_captured_file(
    files: &crate::workspace::ReviewSourceTree,
    file: &ReviewCapturedFile,
    text: Option<&str>,
) -> Result<()> {
    if file.state != ReviewCapturedFileState::Captured {
        anyhow::ensure!(
            text.is_none() && file.blob_hash.is_none() && file.byte_count.is_none(),
            "Omitted source cannot supply code"
        );
        return Ok(());
    }
    let text = text.context("Captured Review code is missing")?;
    anyhow::ensure!(
        file.byte_count == Some(text.len() as u64),
        "Captured Review code size changed"
    );
    let hash = crate::content_store::object_hash(ObjectKind::Blob, text.as_bytes());
    anyhow::ensure!(
        file.blob_hash.as_ref() == Some(&hash),
        "Captured Review code hash changed"
    );
    anyhow::ensure!(
        files.file_hash(&file.path) == Some(hash),
        "Captured Review code is not authenticated by its source tree"
    );
    Ok(())
}

pub(super) fn relative_finding_path(
    workspace: &WorkspaceTarget,
    finding: &Finding,
) -> Result<String> {
    let input = Path::new(&finding.file_path);
    let relative = if input.is_absolute() {
        input.strip_prefix(workspace.root())?
    } else {
        input
    };
    Ok(relative
        .to_str()
        .context("Review source path is not text")?
        .replace('\\', "/"))
}

fn validate_snapshot(workspace: &WorkspaceTarget, document: &ReviewSourceEvidence) -> Result<()> {
    use crate::content_store::{object_hash, TargetSnapshot};
    let hash = crate::identity::Blake3Hash::new(document.snapshot_hash.clone())?;
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_bounded(&hash, ObjectKind::Snapshot, 1024 * 1024)?
        .context("Review evidence snapshot is missing or exceeds its metadata read limit")?;
    anyhow::ensure!(
        object_hash(ObjectKind::Snapshot, &bytes) == hash,
        "Review evidence snapshot failed content authentication"
    );
    let snapshot: TargetSnapshot = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        snapshot.tree_hash.as_str() == document.tree_hash
            && snapshot.workspace_root_fingerprint
                == crate::incremental_index::workspace_root_fingerprint(workspace.root()),
        "Review evidence snapshot belongs to different source or target"
    );
    Ok(())
}
