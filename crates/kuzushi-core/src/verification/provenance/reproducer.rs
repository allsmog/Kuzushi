use super::cases::{calibrated_empirical_cases, validate_empirical_cases, EmpiricalInputCase};
use crate::content_store::{ContentStore, ObjectKind, ObjectRef};
use crate::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const REPRODUCER_SCHEMA_VERSION: u16 = 2;
const MAX_REPRODUCER_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPRODUCER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REPRODUCER_OBJECT_BYTES: u64 = MAX_REPRODUCER_BYTES + 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReproducerInvocation {
    pub(crate) compile_argv: Vec<String>,
    pub(crate) execute_argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmpiricalReproducerSnapshot {
    pub(crate) schema_version: u16,
    pub(crate) language: String,
    pub(crate) invocation: ReproducerInvocation,
    pub(crate) files: Vec<EmpiricalReproducerFile>,
    pub(crate) cases: Vec<EmpiricalInputCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmpiricalReproducerFile {
    pub(crate) path: String,
    pub(crate) source: String,
}

pub(crate) fn persist_empirical_reproducer(
    workspace_root: &Path,
    project_root: &Path,
    language: &str,
    invocation: ReproducerInvocation,
    relative_paths: &[&str],
    original_payload: &[u8],
) -> Result<ObjectRef> {
    let paths = sorted_unique_paths(relative_paths);
    let snapshot = EmpiricalReproducerSnapshot {
        schema_version: REPRODUCER_SCHEMA_VERSION,
        language: language.to_string(),
        invocation,
        files: load_reproducer_files(project_root, &paths)?,
        cases: calibrated_empirical_cases(original_payload)?,
    };
    snapshot.validate()?;
    persist_snapshot(workspace_root, &snapshot)
}

fn sorted_unique_paths<'a>(relative_paths: &[&'a str]) -> Vec<&'a str> {
    let mut paths = relative_paths.to_vec();
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn load_reproducer_files(
    project_root: &Path,
    relative_paths: &[&str],
) -> Result<Vec<EmpiricalReproducerFile>> {
    let mut total_bytes = 0_u64;
    let mut files = Vec::with_capacity(relative_paths.len());
    for relative in relative_paths {
        let path = Path::new(relative);
        validate_reproducer_path(relative)?;
        let source = crate::bounded_file::read_utf8_text_within(
            project_root,
            path,
            MAX_REPRODUCER_FILE_BYTES as usize,
        )
        .with_context(|| format!("could not read reproducer source {relative}"))?;
        total_bytes = add_source_size(total_bytes, source.len())?;
        files.push(EmpiricalReproducerFile {
            path: (*relative).to_string(),
            source,
        });
    }
    Ok(files)
}

fn add_source_size(total_bytes: u64, source_bytes: usize) -> Result<u64> {
    let total_bytes = total_bytes
        .checked_add(source_bytes as u64)
        .context("reproducer source size overflow")?;
    anyhow::ensure!(
        total_bytes <= MAX_REPRODUCER_BYTES,
        "reproducer sources exceed the total size limit"
    );
    Ok(total_bytes)
}

fn persist_snapshot(
    workspace_root: &Path,
    snapshot: &EmpiricalReproducerSnapshot,
) -> Result<ObjectRef> {
    let workspace = WorkspaceTarget::new(workspace_root)?;
    ContentStore::open(workspace.objects_dir())?.put_json(ObjectKind::ProofSnapshot, snapshot)
}

pub(crate) fn load_empirical_reproducer(
    workspace_root: &Path,
    object_ref: &ObjectRef,
) -> Result<EmpiricalReproducerSnapshot> {
    validate_object_ref(object_ref)?;
    let workspace = WorkspaceTarget::new(workspace_root)?;
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_object(object_ref)
        .context("empirical reproducer is missing or corrupt")?;
    let snapshot: EmpiricalReproducerSnapshot =
        serde_json::from_slice(&bytes).context("empirical reproducer JSON is invalid")?;
    snapshot.validate()?;
    Ok(snapshot)
}

fn validate_object_ref(object_ref: &ObjectRef) -> Result<()> {
    anyhow::ensure!(
        object_ref.kind == ObjectKind::ProofSnapshot,
        "empirical reproducer is not a proof snapshot"
    );
    anyhow::ensure!(
        object_ref.size_bytes <= MAX_REPRODUCER_OBJECT_BYTES,
        "empirical reproducer exceeds its strict object-size bound"
    );
    Ok(())
}

impl EmpiricalReproducerSnapshot {
    fn validate(&self) -> Result<()> {
        self.validate_metadata()?;
        let source_bytes = validate_reproducer_files(&self.files)?;
        validate_empirical_cases(&self.cases)?;
        let total = source_bytes
            .checked_add(case_payload_bytes(&self.cases))
            .context("empirical reproducer size overflow")?;
        anyhow::ensure!(
            total as u64 <= MAX_REPRODUCER_BYTES,
            "empirical reproducer exceeds its total read bound"
        );
        Ok(())
    }

    fn validate_metadata(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == REPRODUCER_SCHEMA_VERSION,
            "unsupported empirical reproducer schema version"
        );
        anyhow::ensure!(
            matches!(self.language.as_str(), "rust" | "c" | "cpp"),
            "unsupported empirical reproducer language"
        );
        validate_invocation(&self.invocation)?;
        anyhow::ensure!(
            !self.files.is_empty() && self.files.len() <= 8,
            "invalid empirical reproducer file count"
        );
        Ok(())
    }
}

fn validate_reproducer_files(files: &[EmpiricalReproducerFile]) -> Result<usize> {
    let mut total = 0_usize;
    for file in files {
        validate_reproducer_path(&file.path)?;
        anyhow::ensure!(
            file.source.len() as u64 <= MAX_REPRODUCER_FILE_BYTES,
            "empirical reproducer file exceeds its read bound"
        );
        total = total
            .checked_add(file.source.len())
            .context("empirical reproducer size overflow")?;
    }
    Ok(total)
}

fn case_payload_bytes(cases: &[EmpiricalInputCase]) -> usize {
    cases.iter().map(|case| case.payload.len()).sum()
}

fn validate_invocation(invocation: &ReproducerInvocation) -> Result<()> {
    for argv in [&invocation.compile_argv, &invocation.execute_argv] {
        anyhow::ensure!(
            !argv.is_empty() && argv.len() <= 32,
            "invalid descriptive reproducer invocation"
        );
        anyhow::ensure!(
            argv.iter().all(|arg| !arg.is_empty() && arg.len() <= 1024),
            "invalid descriptive reproducer argument"
        );
    }
    Ok(())
}

fn validate_reproducer_path(relative: &str) -> Result<()> {
    let path = Path::new(relative);
    anyhow::ensure!(
        !path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
        "invalid reproducer source path {relative:?}"
    );
    Ok(())
}
