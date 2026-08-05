use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::build_dataset::{build_review_yield_dataset, DatasetBuild};
use crate::review_yield::domain::{
    canonical_json_bytes, dataset_digest, DatasetManifestV1, DatasetSourceRef,
};
use crate::review_yield::persistence::{read_event_log_head, ReviewYieldProjectionReader};
use crate::workspace::WorkspaceTarget;

pub struct ExportOutcome {
    pub rows: usize,
    pub dataset_path: PathBuf,
    pub manifest_path: PathBuf,
    pub dataset_digest: String,
}

/// Writes the JSONL dataset and its manifest. The caller is responsible for
/// having contained `out` inside the workspace.
///
/// An empty corpus is a valid export: an empty JSONL file plus a manifest whose
/// census explains why no row qualified.
pub fn export_dataset(workspace: &WorkspaceTarget, out: &Path) -> Result<ExportOutcome> {
    let reader = ReviewYieldProjectionReader::open(workspace)?;
    let build = build_review_yield_dataset(&reader, workspace)?;
    let manifest = manifest_for(workspace, &build)?;
    let row_lines = row_lines(&build)?;
    let manifest = seal(manifest, &row_lines)?;
    let manifest_path = manifest_path_for(out);
    write_file(out, &row_lines.concat())?;
    write_file(&manifest_path, &canonical_json_bytes(&manifest)?)?;
    Ok(ExportOutcome {
        rows: build.rows.len(),
        dataset_path: out.to_path_buf(),
        manifest_path,
        dataset_digest: manifest.dataset_digest,
    })
}

/// `<out>.manifest.json`, so the manifest always travels beside its dataset.
pub fn manifest_path_for(out: &Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(".manifest.json");
    out.with_file_name(name)
}

fn manifest_for(workspace: &WorkspaceTarget, build: &DatasetBuild) -> Result<DatasetManifestV1> {
    let head = read_event_log_head(workspace)?;
    let source = DatasetSourceRef {
        event_log_head_seq: head.seq,
        event_log_head_hash: head.hash,
        projection_applied_seq: build.census.projection_applied_seq,
        projection_generation: build.census.projection_generation,
    };
    Ok(DatasetManifestV1::new(
        build.census.clone(),
        source,
        build.rows.len() as u64,
    ))
}

/// One canonical JSON line per row, in exported order. These exact bytes are
/// both written to disk and fed to the digest.
fn row_lines(build: &DatasetBuild) -> Result<Vec<Vec<u8>>> {
    build
        .rows
        .iter()
        .map(|row| {
            let mut line = canonical_json_bytes(row)?;
            line.push(b'\n');
            Ok(line)
        })
        .collect()
}

fn seal(mut manifest: DatasetManifestV1, row_lines: &[Vec<u8>]) -> Result<DatasetManifestV1> {
    let manifest_bytes = manifest.canonical_bytes_without_digest()?;
    let mut parts: Vec<&[u8]> = vec![manifest_bytes.as_slice()];
    parts.extend(row_lines.iter().map(Vec::as_slice));
    manifest.dataset_digest = dataset_digest(&parts);
    Ok(manifest)
}

fn write_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    crate::fs_atomic::write_atomic_bytes(path, contents)
        .with_context(|| format!("could not write {}", path.display()))
}
