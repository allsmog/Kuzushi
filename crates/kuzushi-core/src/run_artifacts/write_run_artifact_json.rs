use super::artifact_manifest::{record_run_artifact, record_run_artifact_object};
use super::*;
use crate::artifact_contract::{CanonicalRunArtifactSpec, canonical_run_artifact_spec};
use crate::content_store::{ContentStore, ObjectKind};
use crate::workspace::workspace_objects_dir;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub fn write_run_artifact_json(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    value: &Value,
) -> Result<RunArtifact> {
    let target = target.as_ref();
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = run_artifact_path(target, run_id, leaf);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    // Critical run state: write crash-safely so a mid-write abort leaves the
    // prior artifact intact rather than a truncated JSON document.
    let body = format!("{}\n", serde_json::to_string_pretty(value)?);
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    let label = label.into();
    let path = path.display().to_string();
    let artifact = RunArtifact::from_declared(&label, &path, Some("json"))
        .context("run artifact path must not be empty")?;
    record_run_artifact(target, run_id, &artifact)?;
    let object_ref = ContentStore::open(workspace_objects_dir(target))?
        .put_bytes(json_artifact_object_kind(leaf), body.as_bytes())?;
    record_run_artifact_object(target, run_id, &artifact, object_ref)?;
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
    let dir = run_dir(&target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = run_artifact_path(&target, run_id, run_trace_spec().leaf);
    reject_non_file_trace_target(&path)?;

    // Serialize raw appends to this trace file across all in-process callers.
    // This protects record framing: two writers cannot interleave partial JSONL
    // lines. Semantic `n` ordering for TraceHandle producers is enforced by the
    // handle's number+record emission lock before this lower-level append.
    let append_lock = trace_append_lock(&path);
    let _guard = append_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut line = serde_json::to_string(step)?;
    line.push('\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

/// Per-trace-file append lock registry. Guarantees that concurrent appends to
/// the same run's `trace.jsonl` are serialized within the process, keeping
/// record framing deterministic.
fn trace_append_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(
        map.entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

pub fn next_run_trace_step_number(target: impl AsRef<Path>, run_id: &str) -> usize {
    let path = run_artifact_path(target, run_id, run_trace_spec().leaf);
    let Ok(text) = fs::read_to_string(path) else {
        return 1;
    };
    crate::run_artifacts::jsonl_numbering::next_jsonl_number::<RunTraceStep>(&text, |step| step.n)
}

fn run_trace_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("runtime trace artifact must be in shared spec")
}

fn reject_non_file_trace_target(path: &Path) -> Result<()> {
    match fs::metadata(path) {
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
