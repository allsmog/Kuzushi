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
    let candidates: Vec<(&str, &str)> = match module_id {
        "context" => vec![(".kuzushi/context-snapshot.json", "context snapshot")],
        "threat-model" => vec![
            (".kuzushi/threat-model.json", "persisted threat model"),
            (
                ".kuzushi/tm-artifacts/normalized-threat-model.json",
                "normalized threat model",
            ),
        ],
        "carlini-threat-hunt" => vec![
            (".kuzushi/threat-model.json", "required threat-model input"),
            (".kuzushi/v2/findings.sqlite3", "hunt findings database"),
        ],
        "x-ray" => vec![
            ("x-ray/x-ray.md", "x-ray report"),
            ("x-ray/entry-points.md", "entry point report"),
            ("x-ray/invariants.md", "invariants report"),
            ("x-ray/architecture.svg", "architecture diagram"),
        ],
        _ => Vec::new(),
    };

    Ok(candidates
        .into_iter()
        .map(|(path, description)| KnownArtifact {
            module_id: module_id.to_string(),
            path: path.to_string(),
            description: description.to_string(),
            exists: workspace.root().join(path).exists(),
        })
        .collect())
}

pub(crate) fn ensure_supported_module(module_id: &str) -> Result<()> {
    if !is_supported_attachment_module(module_id) {
        anyhow::bail!(
            "KB attachments support context, threat-model, carlini-threat-hunt, and x-ray; got {module_id:?}. Next: kb context"
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
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
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
