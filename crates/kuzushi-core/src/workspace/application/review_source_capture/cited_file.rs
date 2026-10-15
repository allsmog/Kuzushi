//! Read only the exact file bytes authenticated by the captured tree.
use super::*;
use crate::content_store::object_hash;
use crate::findings::{ReviewCapturedFile, ReviewCapturedFileState};
mod tree;
pub(crate) use tree::ReviewSourceTree;

pub const MAX_REVIEW_SOURCE_BYTES: usize = 256 * 1024;

pub(crate) fn capture_cited_file(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    tree_hash: &str,
    limit: usize,
) -> Result<ReviewCapturedFile> {
    let tree = ReviewSourceTree::load(workspace, tree_hash)?;
    capture_cited_file_from_tree(workspace, finding, &tree, limit)
}

pub(crate) fn capture_cited_file_from_tree(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    tree: &ReviewSourceTree,
    limit: usize,
) -> Result<ReviewCapturedFile> {
    anyhow::ensure!(
        (1..=MAX_REVIEW_SOURCE_BYTES).contains(&limit),
        "Cited source limit must be 1 to 262144 bytes"
    );
    let path = relative_source_path(workspace, &finding.file_path)?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let expected = tree.file_hash(&path);
    let Some(expected) = expected else {
        return Ok(omitted(path, ReviewCapturedFileState::ExcludedOrMissing));
    };
    let Some(bytes) = read_current_bytes(workspace, &path, limit)? else {
        return Ok(omitted(path, ReviewCapturedFileState::TooLarge));
    };
    store_captured_bytes(&store, path, bytes, expected)
}

fn store_captured_bytes(
    store: &ContentStore,
    path: String,
    bytes: Vec<u8>,
    expected: Blake3Hash,
) -> Result<ReviewCapturedFile> {
    anyhow::ensure!(
        object_hash(ObjectKind::Blob, &bytes) == expected,
        "Cited source changed during capture; capture it again"
    );
    if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Ok(omitted(path, ReviewCapturedFileState::BinaryOrInvalidText));
    }
    let blob = store.put_blob(&bytes)?;
    Ok(ReviewCapturedFile {
        path,
        state: ReviewCapturedFileState::Captured,
        blob_hash: Some(blob.hash),
        byte_count: Some(bytes.len() as u64),
    })
}

fn read_current_bytes(
    workspace: &WorkspaceTarget,
    path: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    let full = workspace.root().join(path);
    ensure_regular_source_path(workspace, &full)?;
    let file = crate::bounded_file::open_regular_file(&full)?;
    if file.metadata()?.len() > limit as u64 {
        return Ok(None);
    }
    Ok(Some(crate::bounded_file::read_open_regular_bytes(
        &full, file, limit,
    )?))
}

fn relative_source_path(workspace: &WorkspaceTarget, raw: &str) -> Result<String> {
    let input = std::path::Path::new(raw);
    let relative = if input.is_absolute() {
        input
            .strip_prefix(workspace.root())
            .context("Cited source is outside this target")?
    } else {
        input
    };
    let path = relative.to_str().context("Cited path is not valid text")?;
    crate::findings::safe_target_path(workspace.root(), path)
        .context("Cited source path must stay inside this target")?;
    Ok(path.replace('\\', "/"))
}

fn ensure_regular_source_path(workspace: &WorkspaceTarget, path: &std::path::Path) -> Result<()> {
    let relative = path.strip_prefix(workspace.root())?;
    let mut current = workspace.root().to_path_buf();
    for part in relative.components() {
        current.push(part);
        anyhow::ensure!(
            !std::fs::symlink_metadata(&current)?
                .file_type()
                .is_symlink(),
            "Cited source became a symlink; capture it again"
        );
    }
    Ok(())
}

fn omitted(path: String, state: ReviewCapturedFileState) -> ReviewCapturedFile {
    ReviewCapturedFile {
        path,
        state,
        blob_hash: None,
        byte_count: None,
    }
}

pub fn read_captured_review_code(
    workspace: &WorkspaceTarget,
    source: &ReviewSourceCapture,
) -> Result<Option<String>> {
    anyhow::ensure!(
        source.target_identity == super::target_identity(workspace),
        "Captured code belongs to another target"
    );
    let Some(file) = &source.cited_file else {
        return Ok(None);
    };
    read_captured_file(workspace, file)
}

pub(crate) fn read_captured_file(
    workspace: &WorkspaceTarget,
    file: &ReviewCapturedFile,
) -> Result<Option<String>> {
    if file.state != ReviewCapturedFileState::Captured {
        return Ok(None);
    }
    let hash = file
        .blob_hash
        .as_ref()
        .context("Captured file has no content reference")?;
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_blob_bounded(hash, MAX_REVIEW_SOURCE_BYTES)?
        .context("Captured code is unavailable or exceeds its read limit")?;
    anyhow::ensure!(
        Some(bytes.len() as u64) == file.byte_count,
        "Captured code size does not match its receipt"
    );
    Ok(Some(
        String::from_utf8(bytes).context("Captured code is not valid text")?,
    ))
}
