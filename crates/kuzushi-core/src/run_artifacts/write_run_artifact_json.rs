use super::artifact_manifest::record_run_artifact_object_under_lock;
use super::*;
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};
use crate::content_store::{ContentStore, ObjectKind};
use crate::workspace::workspace_objects_dir;

#[derive(Debug, Clone, PartialEq)]
pub struct RunTraceRead {
    pub steps: Vec<RunTraceStep>,
    pub malformed_lines: usize,
}

pub fn load_run_trace(target: impl AsRef<Path>, run_id: &str) -> Result<RunTraceRead> {
    let body = super::run_artifact_reader::read_run_artifact_text_or_empty(
        target,
        run_id,
        run_trace_spec().leaf,
        "Run trace",
    )?;
    Ok(parse_run_trace_lines(&body))
}

fn parse_run_trace_lines(body: &str) -> RunTraceRead {
    let mut read = RunTraceRead {
        steps: Vec::new(),
        malformed_lines: 0,
    };
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<RunTraceStep>(line) {
            Ok(step) => read.steps.push(step),
            Err(_) => read.malformed_lines += 1,
        }
    }
    read
}

pub fn write_run_artifact_json(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    value: &Value,
) -> Result<RunArtifact> {
    let target = target.as_ref();
    ensure_run_artifact_parent(target, run_id, leaf)?;
    let path = checked_run_artifact_path(target, run_id, leaf)?;
    // Critical run state: write crash-safely so a mid-write abort leaves the
    // prior artifact intact rather than a truncated JSON document.
    let body = format!("{}\n", serde_json::to_string_pretty(value)?);
    let label = label.into();
    let declared_path = path.display().to_string();
    let artifact = RunArtifact::from_declared(&label, &declared_path, Some("json"))
        .context("run artifact path must not be empty")?;
    let object_ref = ContentStore::open(workspace_objects_dir(target))?
        .put_bytes(json_artifact_object_kind(leaf), body.as_bytes())?;
    let guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    record_run_artifact_object_under_lock(target, run_id, &artifact, object_ref, &guard)?;
    Ok(artifact)
}

fn json_artifact_object_kind(leaf: &str) -> ObjectKind {
    match leaf {
        "context.json" => ObjectKind::ContextSnapshot,
        "attack-surface.json" => ObjectKind::AttackSurfaceSnapshot,
        "findings.json" => ObjectKind::FindingObservationBatch,
        "proof.json" => ObjectKind::ProofSnapshot,
        "failures.json" => ObjectKind::DiagnosticBundle,
        _ => ObjectKind::Blob,
    }
}

pub fn append_run_trace_step(
    target: impl AsRef<Path>,
    run_id: &str,
    step: &RunTraceStep,
) -> Result<PathBuf> {
    let target = target.as_ref();
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    let path = checked_run_artifact_path(target, run_id, run_trace_spec().leaf)?;
    reject_non_file_trace_target(&path)?;
    append_trace_step_locked(&path, step)?;
    Ok(path)
}

pub fn append_run_trace_step_with_next_number(
    target: impl AsRef<Path>,
    run_id: &str,
    step: &RunTraceStep,
) -> Result<PathBuf> {
    let target = target.as_ref();
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    let path = checked_run_artifact_path(target, run_id, run_trace_spec().leaf)?;
    reject_non_file_trace_target(&path)?;
    let mut numbered = step.clone();
    numbered.n = next_trace_step_number_from_path(&path)?;
    append_trace_step_locked(&path, &numbered)?;
    Ok(path)
}

pub fn next_run_trace_step_number(target: impl AsRef<Path>, run_id: &str) -> usize {
    checked_run_artifact_path(target, run_id, run_trace_spec().leaf)
        .and_then(|path| next_trace_step_number_from_path(&path))
        .unwrap_or(1)
}

fn next_trace_step_number_from_path(path: &Path) -> Result<usize> {
    let text = match crate::bounded_file::read_utf8_text(
        path,
        super::run_artifact_reader::MAX_RUN_ARTIFACT_READ_BYTES as usize,
    ) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Could not read run trace {}", path.display()))
        }
    };
    Ok(crate::run_artifacts::jsonl_numbering::next_jsonl_number::<
        RunTraceStep,
    >(&text, |step| step.n))
}

fn append_trace_step_locked(path: &Path, step: &RunTraceStep) -> Result<()> {
    let mut line = serde_json::to_string(step)?;
    line.push('\n');
    super::jsonl_append::append_jsonl_line(path, &line)
}

fn run_trace_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("runtime trace artifact must be in shared spec")
}

fn reject_non_file_trace_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Run trace target must not be a symlink: {}", path.display())
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("Run trace target is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
