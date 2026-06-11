use super::*;

pub fn reparse_source(workspace: &WorkspaceTarget, id: &str) -> Result<AttachmentRecord> {
    let store = load_store(workspace)?;
    let Some(existing) = store.attachments.iter().find(|record| record.id == id) else {
        anyhow::bail!("{}", attachment_id_error(id, &store.attachments));
    };
    let reparsed = match existing.kind {
        AttachmentKind::Path => {
            build_path_record(workspace, &existing.module_id, &existing.source)?
        }
        AttachmentKind::Url => build_url_record(&existing.module_id, &existing.source)?,
    };
    upsert_record(workspace, reparsed)
}

pub fn known_artifacts(workspace: &WorkspaceTarget, module_id: &str) -> Result<Vec<KnownArtifact>> {
    ensure_supported_module(module_id)?;
    Ok(known_artifact_candidates(workspace, module_id)
        .into_iter()
        .map(|(path, description)| KnownArtifact {
            module_id: module_id.to_string(),
            path: path.clone(),
            description: description.to_string(),
            exists: workspace.root().join(path).exists(),
        })
        .collect())
}

fn known_artifact_candidates(
    workspace: &WorkspaceTarget,
    module_id: &str,
) -> Vec<(String, &'static str)> {
    match module_id {
        "context" => context_known_artifacts(workspace),
        "threat-model" => threat_model_known_artifacts(workspace),
        "carlini-threat-hunt" | "offense-review" => offense_review_known_artifacts(workspace),
        "x-ray" => x_ray_known_artifacts(),
        _ => Vec::new(),
    }
}

fn context_known_artifacts(workspace: &WorkspaceTarget) -> Vec<(String, &'static str)> {
    vec![(
        known_artifact_relative_path(workspace, |root| crate::context::context_snapshot_path(root)),
        "context snapshot",
    )]
}

fn threat_model_known_artifacts(workspace: &WorkspaceTarget) -> Vec<(String, &'static str)> {
    vec![
        (
            known_artifact_relative_path(workspace, |root| {
                crate::capabilities::persistent_threat_model_path(root)
            }),
            "persisted threat model",
        ),
        (
            ".kuzushi/tm-artifacts/normalized-threat-model.json".to_string(),
            "normalized threat model",
        ),
    ]
}

fn offense_review_known_artifacts(workspace: &WorkspaceTarget) -> Vec<(String, &'static str)> {
    vec![
        (
            known_artifact_relative_path(workspace, |root| {
                crate::capabilities::persistent_threat_model_path(root)
            }),
            "required threat-model input",
        ),
        (
            known_artifact_relative_path(workspace, |root| {
                crate::workspace::workspace_findings_db_path(root)
            }),
            "hunt findings database",
        ),
    ]
}

fn x_ray_known_artifacts() -> Vec<(String, &'static str)> {
    vec![
        ("x-ray/x-ray.md".to_string(), "x-ray report"),
        ("x-ray/entry-points.md".to_string(), "entry point report"),
        ("x-ray/invariants.md".to_string(), "invariants report"),
        ("x-ray/architecture.svg".to_string(), "architecture diagram"),
    ]
}

fn known_artifact_relative_path(
    workspace: &WorkspaceTarget,
    artifact_path: impl FnOnce(&Path) -> PathBuf,
) -> String {
    let path = artifact_path(workspace.root());
    path
        .strip_prefix(workspace.root())
        .unwrap_or(&path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn ensure_supported_module(module_id: &str) -> Result<()> {
    if !is_supported_attachment_module(module_id) {
        anyhow::bail!(
            "KB attachments support context, threat-model, offense-review, and x-ray; got {module_id:?}. Next: kb context"
        );
    }
    Ok(())
}

pub(crate) fn load_store(workspace: &WorkspaceTarget) -> Result<AttachmentStoreFile> {
    let path = attachment_store_path(workspace);
    if !path.exists() {
        return Ok(AttachmentStoreFile::default());
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    if value.is_array() {
        let attachments = serde_json::from_value(value)
            .with_context(|| format!("Could not parse {}", path.display()))?;
        return Ok(AttachmentStoreFile {
            version: 1,
            attachments,
        });
    }
    serde_json::from_value(value).with_context(|| format!("Could not parse {}", path.display()))
}

pub(crate) fn save_store(workspace: &WorkspaceTarget, store: &AttachmentStoreFile) -> Result<()> {
    workspace.ensure_state_dir()?;
    let path = attachment_store_path(workspace);
    let body = format!("{}\n", serde_json::to_string_pretty(store)?);
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))
}

pub(crate) fn upsert_record(
    workspace: &WorkspaceTarget,
    record: AttachmentRecord,
) -> Result<AttachmentRecord> {
    let mut store = load_store(workspace)?;
    if let Some(existing) = store
        .attachments
        .iter_mut()
        .find(|existing| existing.id == record.id)
    {
        *existing = record.clone();
    } else {
        store.attachments.push(record.clone());
    }
    save_store(workspace, &store)?;
    Ok(record)
}
