//! Reuse the existing CAS for authenticated, bounded scan-context snapshots.
use crate::content_store::{ContentStore, ObjectKind};
use crate::scan::{ScanContextDocument, ScanContextRef};
use crate::WorkspaceTarget;
use anyhow::{Context, Result};
use std::path::Path;

const MAX_SCAN_CONTEXT_BYTES: usize = 64 * 1024;

pub(crate) fn save_scan_context(
    root: &Path,
    document: &ScanContextDocument,
) -> Result<ScanContextRef> {
    let bytes = serde_json::to_vec(document)?;
    anyhow::ensure!(
        bytes.len() <= MAX_SCAN_CONTEXT_BYTES,
        "Supporting scan context exceeds 64 KiB; refine the context before preparing this plan"
    );
    let workspace = WorkspaceTarget::new(root)?;
    let object = ContentStore::open(workspace.objects_dir())?.put_blob(&bytes)?;
    Ok(ScanContextRef {
        schema_version: 1,
        object,
    })
}

pub(crate) fn load_scan_context(
    root: &Path,
    reference: &ScanContextRef,
) -> Result<ScanContextDocument> {
    anyhow::ensure!(
        reference.schema_version == 1 && reference.object.kind == ObjectKind::Blob,
        "Unsupported scan-context reference"
    );
    anyhow::ensure!(
        reference.object.size_bytes <= MAX_SCAN_CONTEXT_BYTES as u64,
        "Scan context exceeds its read limit"
    );
    let workspace = WorkspaceTarget::new(root)?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let bytes = store.get_blob_bounded(&reference.object.hash, MAX_SCAN_CONTEXT_BYTES)?
        .context("Frozen scan context is missing or exceeds its read limit; inspect the plan before further work")?;
    anyhow::ensure!(
        bytes.len() as u64 == reference.object.size_bytes,
        "Scan-context size does not match its reference"
    );
    let document: ScanContextDocument = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        document.schema_version == 1,
        "Unsupported scan-context document"
    );
    anyhow::ensure!(
        document.target == workspace.root().canonicalize()?.to_string_lossy(),
        "Frozen scan context belongs to a different target"
    );
    Ok(document)
}
