//! Typed, bounded CAS storage for a frozen scanner-context projection.
use crate::content_store::{ContentStore, ObjectKind};
use crate::scan::{ScanContextRef, ThreatModelDigestDocument};
use crate::WorkspaceTarget;
use anyhow::{Context, Result};
use std::path::Path;

const MAX_DIGEST_BYTES: usize = 512 * 1024;

pub(crate) fn save_threat_model_digest(
    root: &Path,
    document: &ThreatModelDigestDocument,
) -> Result<ScanContextRef> {
    let bytes = serde_json::to_vec(document)?;
    anyhow::ensure!(bytes.len() <= MAX_DIGEST_BYTES,
        "Scanner threat-model context exceeds 512 KiB; inspect and refine the context before preparing this plan");
    let workspace = WorkspaceTarget::new(root)?;
    let object = ContentStore::open(workspace.objects_dir())?.put_blob(&bytes)?;
    Ok(ScanContextRef {
        schema_version: 1,
        object,
    })
}

pub(crate) fn load_threat_model_digest(
    root: &Path,
    reference: &ScanContextRef,
) -> Result<ThreatModelDigestDocument> {
    anyhow::ensure!(
        reference.schema_version == 1 && reference.object.kind == ObjectKind::Blob,
        "Unsupported frozen threat-model context reference"
    );
    anyhow::ensure!(
        reference.object.size_bytes <= MAX_DIGEST_BYTES as u64,
        "Frozen threat-model context exceeds its read limit"
    );
    let workspace = WorkspaceTarget::new(root)?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let bytes = store.get_blob_bounded(&reference.object.hash, MAX_DIGEST_BYTES)?
        .context("Frozen scanner context is missing; retain recorded work and prepare a replacement plan before further execution")?;
    anyhow::ensure!(
        bytes.len() as u64 == reference.object.size_bytes,
        "Frozen scanner-context size differs from its reference"
    );
    let document: ThreatModelDigestDocument = serde_json::from_slice(&bytes)?;
    validate_document(&workspace, &document)?;
    Ok(document)
}

fn validate_document(
    workspace: &WorkspaceTarget,
    document: &ThreatModelDigestDocument,
) -> Result<()> {
    anyhow::ensure!(
        document.schema_version == 1 && document.kind == "threat-model-digest",
        "Unsupported frozen scanner-context document"
    );
    anyhow::ensure!(
        document.target == workspace.root().canonicalize()?.to_string_lossy(),
        "Frozen scanner context belongs to a different target"
    );
    let preview = &document.preview;
    anyhow::ensure!(
        preview["schemaVersion"] == 1 && preview["kind"] == "agentic-threat-model-digest",
        "Frozen scanner-context projection is invalid"
    );
    validate_text(preview)
}

fn validate_text(preview: &serde_json::Value) -> Result<()> {
    let valid = match preview.get("text") {
        Some(serde_json::Value::String(text)) => {
            preview["sha256"].as_str() == Some(crate::prompt_content_sha256(text).as_str())
        }
        Some(serde_json::Value::Null) => preview["sha256"].is_null(),
        _ => false,
    };
    anyhow::ensure!(valid, "Frozen scanner-context text hash is invalid");
    Ok(())
}
