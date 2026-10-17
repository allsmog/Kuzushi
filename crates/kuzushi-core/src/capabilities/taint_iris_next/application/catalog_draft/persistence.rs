use super::*;

pub(super) struct CatalogAcceptance {
    pub digest: String,
    pub previous_digest: Option<String>,
    pub changed: bool,
}

pub(super) fn reference(input: &Value) -> Result<String> {
    let value = input["draftRef"]
        .as_str()
        .context("Choose an exact draftRef from a completed catalog job")?;
    Ok(crate::identity::Blake3Hash::new(value.into())?.to_string())
}

pub(super) fn save(root: &Path, draft: &CatalogDraft) -> Result<String> {
    let bytes = serde_json::to_vec(draft)?;
    anyhow::ensure!(
        bytes.len() <= MAX_DRAFT_BYTES,
        "Catalog draft exceeds 256 KiB"
    );
    let workspace = crate::WorkspaceTarget::new(root)?;
    let reference = ContentStore::open(workspace.objects_dir())?.put_blob(&bytes)?;
    Ok(reference.hash.to_string())
}

pub(super) fn load(root: &Path, reference: &str) -> Result<CatalogDraft> {
    let hash = crate::identity::Blake3Hash::new(reference.into())?;
    let workspace = crate::WorkspaceTarget::new(root)?;
    anyhow::ensure!(
        workspace.objects_dir().join("blake3").is_dir(),
        "Catalog draft store is missing; inspect the original job"
    );
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_blob_bounded(&hash, MAX_DRAFT_BYTES)?
        .context("Catalog draft is missing or exceeds 256 KiB")?;
    let draft: CatalogDraft =
        serde_json::from_slice(&bytes).context("Catalog draft is malformed")?;
    anyhow::ensure!(
        draft.schema_version == 1 && draft.kind == "taint-catalog-draft",
        "Unsupported catalog draft format"
    );
    anyhow::ensure!(
        draft.target == root.canonicalize()?.to_string_lossy(),
        "Catalog draft belongs to a different target"
    );
    anyhow::ensure!(
        (1..=12).contains(&draft.catalog.len()),
        "Catalog draft entry count is invalid"
    );
    Ok(draft)
}

pub(super) fn active_bytes(root: &Path) -> Result<Option<Vec<u8>>> {
    let path = taint_iris_next_target_catalog_path(root);
    match crate::bounded_file::read_utf8_text_within(root, &path, 8 * 1024 * 1024) {
        Ok(text) => Ok(Some(text.into_bytes())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn active_digest(root: &Path) -> Result<Option<String>> {
    Ok(active_bytes(root)?
        .map(|bytes| crate::content_store::object_hash(ObjectKind::Blob, &bytes).to_string()))
}

pub(super) fn accept(
    root: &Path,
    reference: &str,
    draft: &CatalogDraft,
    ctx: &ToolExecutionContext<'_>,
    expected_active: Option<&str>,
) -> Result<CatalogAcceptance> {
    let _guard = catalog_lock(root, &|| ctx.is_cancelled())?;
    let current = crate::workspace::source_snapshot::inspect_current_source_hash(
        ctx,
        "taint-iris-next:catalog-accept",
        root,
    )?;
    anyhow::ensure!(current == draft.source_tree_hash, "Source changed since catalog generation; historical draft remains readable, but acceptance needs a new draft");
    let payload = accepted_payload(draft, reference);
    let expected_digest =
        crate::content_store::object_hash(ObjectKind::Blob, &serde_json::to_vec_pretty(&payload)?)
            .to_string();
    let current_digest = active_digest(root)?;
    validate_replacement(
        draft,
        current_digest.as_deref(),
        &expected_digest,
        expected_active,
    )?;
    if current_digest.as_deref() == Some(expected_digest.as_str()) {
        return Ok(CatalogAcceptance {
            digest: expected_digest,
            previous_digest: None,
            changed: false,
        });
    }
    replace_profile(root, &payload, &expected_digest, current_digest, ctx)
}

fn replace_profile(
    root: &Path,
    payload: &Value,
    expected_digest: &str,
    current_digest: Option<String>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CatalogAcceptance> {
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Catalog acceptance canceled before publication"
    );
    if let Some(bytes) = active_bytes(root)? {
        archive_profile(root, &bytes)?;
    }
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Catalog acceptance canceled before replacement"
    );
    super::super::dynamic_catalog::persist_catalog_payload_unlocked(root, payload)?;
    Ok(CatalogAcceptance {
        digest: expected_digest.into(),
        previous_digest: current_digest,
        changed: true,
    })
}

pub(super) fn artifact(root: &Path, reference: &str, label: &str) -> Result<Value> {
    let hash = crate::identity::Blake3Hash::new(reference.into())?;
    let workspace = crate::WorkspaceTarget::new(root)?;
    let path = ContentStore::open(workspace.objects_dir())?.object_path(&hash);
    Ok(json!({"path":path,"label":label,"kind":"json"}))
}

fn accepted_payload(draft: &CatalogDraft, reference: &str) -> Value {
    json!({"kind":"taint-catalog-accepted","target":draft.target,"catalog":draft.catalog,
        "acceptedDraftRef":reference,"sourceTreeHash":draft.source_tree_hash,"schemaVersion":1})
}

fn validate_replacement(
    draft: &CatalogDraft,
    current: Option<&str>,
    accepted: &str,
    expected: Option<&str>,
) -> Result<()> {
    if expected.is_none() && current == Some(accepted) {
        return Ok(());
    }
    let expected = match expected {
        Some("absent") => None,
        Some(value) => {
            crate::identity::Blake3Hash::new(value.into())?;
            Some(value)
        }
        None => draft.base_catalog_digest.as_deref(),
    };
    anyhow::ensure!(current == expected, "Active catalog changed since this draft; inspect catalog-read, then explicitly approve expectedActiveDigest to replace that exact version. No regeneration is required while source is unchanged");
    Ok(())
}

pub(crate) fn catalog_lock(
    root: &Path,
    canceled: &dyn Fn() -> bool,
) -> Result<crate::file_lock::ExclusiveFileLock> {
    crate::WorkspaceTarget::new(root)?.ensure_state_dir()?;
    crate::file_lock::ExclusiveFileLock::acquire_cancellable(
        &crate::workspace::workspace_state_root(root).join("taint-catalog.lock"),
        canceled,
    )
}

pub(crate) fn selected_catalog(
    root: &Path,
    expected: Option<&str>,
) -> Result<Option<Vec<TaintIrisNextRankedCatalogEntry>>> {
    if expected == Some("static") {
        return Ok(None);
    }
    let Some(expected) = expected else {
        anyhow::ensure!(active_bytes(root)?.is_none(), "Saved catalog requires an exact catalogDigestRef; use catalog-read to inspect and pin it, or explicitly choose catalogDigestRef=static");
        return Ok(None);
    };
    let (_, value) = profile(root, Some(expected))?.context("Pinned catalog is missing")?;
    ensure_catalog_source_current(root, &value)?;
    super::super::dynamic_catalog::parse_target_catalog_payload(&serde_json::to_string(&value)?)
        .map(Some)
}

pub(crate) fn archive_profile(root: &Path, bytes: &[u8]) -> Result<()> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    ContentStore::open(workspace.objects_dir())?.put_blob(bytes)?;
    Ok(())
}

pub(super) fn profile(root: &Path, reference: Option<&str>) -> Result<Option<(String, Value)>> {
    let Some((digest, bytes)) = raw_profile(root, reference)? else {
        return Ok(None);
    };
    Ok(Some((digest, parse_profile(root, &bytes)?)))
}

pub(super) fn raw_profile(
    root: &Path,
    reference: Option<&str>,
) -> Result<Option<(String, Vec<u8>)>> {
    let bytes = match reference {
        Some(reference) => pinned_bytes(root, reference)?,
        None => active_bytes(root)?,
    };
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let digest = crate::content_store::object_hash(ObjectKind::Blob, &bytes).to_string();
    Ok(Some((digest, bytes)))
}

pub(super) fn parse_profile(root: &Path, bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes)
        .context("Saved catalog is malformed; static fallback was not used")?;
    anyhow::ensure!(
        value["kind"] != "taint-catalog-draft",
        "This is an unaccepted draft; inspect draftRef, then explicitly accept it before scan use"
    );
    if let Some(target) = value["target"].as_str() {
        anyhow::ensure!(
            target == root.canonicalize()?.to_string_lossy(),
            "Catalog belongs to another target"
        );
    }
    Ok(value)
}

fn pinned_bytes(root: &Path, reference: &str) -> Result<Option<Vec<u8>>> {
    let hash = crate::identity::Blake3Hash::new(reference.into())?;
    let workspace = crate::WorkspaceTarget::new(root)?;
    if workspace.objects_dir().join("blake3").is_dir() {
        if let Some(bytes) =
            ContentStore::open(workspace.objects_dir())?.get_blob_bounded(&hash, 8 * 1024 * 1024)?
        {
            return Ok(Some(bytes));
        }
    }
    let bytes = active_bytes(root)?.context("Pinned catalog object is missing")?;
    anyhow::ensure!(
        crate::content_store::object_hash(ObjectKind::Blob, &bytes) == hash,
        "Pinned catalog object is missing; the active catalog has a different digest"
    );
    Ok(Some(bytes))
}

fn ensure_catalog_source_current(root: &Path, value: &Value) -> Result<()> {
    let Some(expected) = value["sourceTreeHash"].as_str() else {
        return Ok(());
    };
    let actual = crate::incremental_index::current_workspace_tree_hash(root)?;
    anyhow::ensure!(
        actual == expected,
        "Accepted catalog source changed; select a new catalog draft for this revision"
    );
    Ok(())
}
