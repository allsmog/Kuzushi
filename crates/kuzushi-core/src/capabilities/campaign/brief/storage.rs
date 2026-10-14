use super::domain::*;
use super::*;
use crate::content_store::ContentStore;
use crate::workspace::{read_optional_workspace_text, write_workspace_state_file};
use crate::WorkspaceTarget;
use std::path::PathBuf;

fn relative(id: &str, leaf: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(PathBuf::from(".kuzushi/v3/investigation-briefs")
        .join(id)
        .join(leaf))
}

pub fn load_current_brief(root: &Path, id: &str) -> Result<Option<BriefRevision>> {
    let path = root.join(relative(id, "head.json")?);
    let Some(text) = read_optional_workspace_text(root, &path, 2048)? else {
        return Ok(None);
    };
    let reference: BriefReference =
        serde_json::from_str(&text).context("Brief head is malformed")?;
    anyhow::ensure!(
        reference.brief_id == id,
        "Brief head belongs to a different id"
    );
    load_brief(root, &reference).map(Some)
}

pub fn load_brief(root: &Path, reference: &BriefReference) -> Result<BriefRevision> {
    reference.validate()?;
    validate_publication(root, reference)?;
    let workspace = WorkspaceTarget::new(root)?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let bytes = store
        .get_blob_bounded(&reference.object.hash, MAX_DOCUMENT_BYTES)?
        .context("Brief object is unavailable")?;
    anyhow::ensure!(
        bytes.len() as u64 == reference.object.size_bytes,
        "Brief object size differs from its reference"
    );
    let document: BriefDocument =
        serde_json::from_slice(&bytes).context("Brief document is malformed")?;
    document.validate(reference, &workspace.root().display().to_string())?;
    Ok(BriefRevision {
        reference: reference.clone(),
        document,
    })
}

fn validate_publication(root: &Path, reference: &BriefReference) -> Result<()> {
    let leaf = format!("revisions/{}.json", reference.revision);
    let path = root.join(relative(&reference.brief_id, &leaf)?);
    let text = read_optional_workspace_text(root, &path, 2048)?
        .context("Brief revision is not published")?;
    let published: BriefReference =
        serde_json::from_str(&text).context("Published brief reference is malformed")?;
    anyhow::ensure!(
        &published == reference,
        "Brief reference differs from its immutable revision"
    );
    Ok(())
}

pub(super) fn save_brief(
    root: &Path,
    id: &str,
    expected: u32,
    text: &str,
    canceled: &dyn Fn() -> bool,
) -> Result<BriefRevision> {
    validate_id(id)?;
    validate_text(text)?;
    let lock =
        crate::workspace::prepare_workspace_output_path(root, relative(id, "revision.lock")?)?;
    let _guard = crate::file_lock::ExclusiveFileLock::acquire_cancellable(&lock, canceled)?;
    let previous = load_current_brief(root, id)?.map(|brief| brief.reference);
    anyhow::ensure!(previous.as_ref().map_or(0, |reference| reference.revision) == expected,
        "Brief revision changed; inspect the current revision before saving. Your text is not overwritten.");
    let document = BriefDocument {
        schema_version: 1,
        brief_id: id.into(),
        revision: expected.checked_add(1).context("Brief revision overflow")?,
        target: WorkspaceTarget::new(root)?.root().display().to_string(),
        text: text.into(),
        previous,
    };
    publish(root, document, canceled)
}

fn publish(
    root: &Path,
    document: BriefDocument,
    canceled: &dyn Fn() -> bool,
) -> Result<BriefRevision> {
    let leaf = format!("revisions/{}.json", document.revision);
    let ordinal = relative(&document.brief_id, &leaf)?;
    let path = crate::workspace::validated_workspace_descendant(root, &ordinal)?;
    anyhow::ensure!(
        !path.exists(),
        "Brief revision ordinal already exists; inspect history before saving"
    );
    let bytes = serde_json::to_vec(&document)?;
    anyhow::ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "Brief document exceeds its storage limit"
    );
    let workspace = WorkspaceTarget::new(root)?;
    let object = ContentStore::open(workspace.objects_dir())?.put_blob(&bytes)?;
    let reference = BriefReference {
        schema_version: 1,
        brief_id: document.brief_id.clone(),
        revision: document.revision,
        object,
    };
    anyhow::ensure!(!canceled(), "Brief save was canceled before publication");
    let body = serde_json::to_vec(&reference)?;
    write_workspace_state_file(root, ordinal, &body)?;
    write_workspace_state_file(root, relative(&document.brief_id, "head.json")?, &body)?;
    Ok(BriefRevision {
        reference,
        document,
    })
}
