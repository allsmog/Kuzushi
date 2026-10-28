//! Freeze explicitly selected historical files without reading the checkout.
use super::*;
use crate::content_store::{ContentStore, ObjectKind};
use crate::identity::Blake3Hash;

const PREFIX: &str = "lesson-source:";
const BUNDLE_LIMIT: usize = 512 * 1024;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LessonSources {
    schema_version: u32,
    origin: LessonOrigin,
    selected_paths: Vec<String>,
    max_bytes: usize,
    pub(super) primary: Value,
    pub(super) supporting: Vec<Value>,
}

pub(super) fn prepare(
    input: &mut Value,
    origin: &LessonOrigin,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if crate::modules::selected_source_paths(input)?.is_empty() {
        anyhow::ensure!(
            input.get("sourceEvidenceRef").is_none(),
            "A lesson source bundle requires supporting-file choices"
        );
        return Ok(());
    }
    let (document, reference) = load(input, origin, ctx)?;
    let reference = match reference {
        Some(reference) => reference,
        None => save(ctx, &document)?,
    };
    input["sourceEvidenceRef"] = json!(reference);
    Ok(())
}

pub(super) fn load(
    input: &Value,
    origin: &LessonOrigin,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(LessonSources, Option<String>)> {
    let current = capture(input, origin, ctx)?;
    let Some(reference) = input.get("sourceEvidenceRef") else {
        let reference = if current.selected_paths.is_empty() {
            None
        } else {
            Some(save(ctx, &current)?)
        };
        return Ok((current, reference));
    };
    let reference = reference
        .as_str()
        .context("sourceEvidenceRef must be a saved lesson reference")?;
    let frozen = read(ctx.workspace.context("Select a lesson target")?, reference)?;
    anyhow::ensure!(
        frozen == current,
        "Lesson source selection or captured evidence changed; prepare a new plan before spending"
    );
    Ok((frozen, Some(reference.into())))
}

fn capture(
    input: &Value,
    origin: &LessonOrigin,
    ctx: &ToolExecutionContext<'_>,
) -> Result<LessonSources> {
    let paths = crate::modules::selected_source_paths(input)?;
    let limit = input["maxSourceBytes"]
        .as_u64()
        .context("maxSourceBytes is required")? as usize;
    anyhow::ensure!(
        (1024..=65536).contains(&limit),
        "Lesson source limit must be 1024 to 65536 bytes"
    );
    let workspace = ctx.workspace.context("Select a lesson target")?;
    let owned = match ctx.findings_store {
        Some(_) => None,
        None => Some(crate::FindingStore::open_read_only(
            workspace.findings_db_path(),
        )?),
    };
    let store = ctx.findings_store.or(owned.as_ref()).unwrap();
    let primary = store.lesson_captured_source(origin, limit)?;
    let remaining = limit.saturating_sub(primary["text"].as_str().map_or(0, str::len));
    let supporting = capture_supporting(ctx, store, origin, &paths, &primary, remaining)?;
    Ok(LessonSources {
        schema_version: 1,
        origin: origin.clone(),
        selected_paths: paths,
        max_bytes: limit,
        primary,
        supporting,
    })
}

fn capture_supporting(
    ctx: &ToolExecutionContext<'_>,
    findings: &crate::FindingStore,
    origin: &LessonOrigin,
    paths: &[String],
    primary: &Value,
    mut remaining: usize,
) -> Result<Vec<Value>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let workspace = ctx.workspace.context("Select a lesson target")?;
    let raw_tree = findings.lesson_source_tree_hash(origin)?;
    let tree = historical_tree(workspace, findings, origin, raw_tree.as_deref())?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let mut sources = Vec::new();
    let primary_path = relative_primary_path(workspace.root(), primary);
    for path in paths
        .iter()
        .filter(|path| Some(path.as_str()) != primary_path.as_deref())
    {
        ctx.ensure_active()?;
        let hash = tree.as_ref().and_then(|tree| tree.file_hash(path));
        let source = historical_file(&store, path, hash, remaining)?;
        remaining = remaining.saturating_sub(source["text"].as_str().map_or(0, str::len));
        sources.push(source);
    }
    Ok(sources)
}

fn historical_file(
    store: &ContentStore,
    path: &str,
    hash: Option<Blake3Hash>,
    remaining: usize,
) -> Result<Value> {
    let Some(hash) = hash else {
        return Ok(
            json!({"path":path,"status":"not_recorded","text":null,"currentSourceRead":false}),
        );
    };
    let bytes = if store.object_path(&hash).try_exists()? {
        store.get_blob_bounded(&hash, remaining)?
    } else {
        None
    };
    let text = bytes.and_then(valid_text);
    let status = if text.is_some() {
        "included"
    } else {
        "unavailable_or_over_limit"
    };
    Ok(json!({"path":path,"blobHash":hash,"status":status,"text":text,"currentSourceRead":false}))
}

fn historical_tree(
    workspace: &crate::WorkspaceTarget,
    findings: &crate::FindingStore,
    origin: &LessonOrigin,
    raw: Option<&str>,
) -> Result<Option<crate::findings::FindingSourceSnapshot>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let hash = Blake3Hash::new(raw.into())?;
    let store = ContentStore::open(workspace.objects_dir())?;
    if !store.object_path(&hash).try_exists()? {
        return Ok(None);
    }
    let snapshot = Blake3Hash::new(origin.snapshot_hash.clone())?;
    if !store.object_path(&snapshot).try_exists()? {
        return Ok(None);
    }
    findings
        .prepare_finding_source_snapshot(workspace.root(), &origin.snapshot_hash, raw)
        .map(Some)
}

fn relative_primary_path(root: &std::path::Path, primary: &Value) -> Option<String> {
    let path = std::path::Path::new(primary["path"].as_str()?);
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_str()
        .map(str::to_string)
}

fn valid_text(bytes: Vec<u8>) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn save(ctx: &ToolExecutionContext<'_>, document: &LessonSources) -> Result<String> {
    let bytes = serde_json::to_vec(document)?;
    anyhow::ensure!(
        bytes.len() <= BUNDLE_LIMIT,
        "Lesson source bundle exceeds 512 KiB"
    );
    let workspace = ctx.workspace.context("Select a lesson target")?;
    let object = ContentStore::open(workspace.objects_dir())?.put_blob(&bytes)?;
    Ok(format!("{PREFIX}{}", object.hash))
}

pub(crate) fn inspect(root: &std::path::Path, reference: &str) -> Result<Value> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    Ok(serde_json::to_value(read(&workspace, reference)?)?)
}

fn read(workspace: &crate::WorkspaceTarget, reference: &str) -> Result<LessonSources> {
    let hash = Blake3Hash::new(
        reference
            .strip_prefix(PREFIX)
            .context("Expected a frozen lesson source reference")?
            .into(),
    )?;
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_bounded(&hash, ObjectKind::Blob, BUNDLE_LIMIT)?
        .context("Frozen lesson source is missing or exceeds 512 KiB")?;
    let document: LessonSources = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        document.schema_version == 1,
        "Unsupported lesson source bundle version"
    );
    anyhow::ensure!(
        document.origin.target == workspace.root().to_string_lossy(),
        "Lesson source belongs to another target"
    );
    document.origin.validate()?;
    Ok(document)
}
