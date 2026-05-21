use super::artifact_manifest::record_run_artifact;
use super::*;

pub fn write_run_artifact_json(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    value: &Value,
) -> Result<RunArtifact> {
    let dir = run_dir(&target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join(leaf);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    let label = label.into();
    let path = path.display().to_string();
    let artifact = RunArtifact::from_declared(&label, &path, Some("json"))
        .context("run artifact path must not be empty")?;
    record_run_artifact(target, run_id, &artifact)?;
    Ok(artifact)
}

pub fn append_run_trace_step(
    target: impl AsRef<Path>,
    run_id: &str,
    step: &RunTraceStep,
) -> Result<PathBuf> {
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("trace.jsonl");
    reject_non_file_trace_target(&path)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(step)?)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn next_run_trace_step_number(target: impl AsRef<Path>, run_id: &str) -> usize {
    let path = run_dir(target, run_id).join("trace.jsonl");
    let Ok(text) = fs::read_to_string(path) else {
        return 1;
    };
    crate::run_artifacts::jsonl_numbering::next_jsonl_number::<RunTraceStep>(&text, |step| step.n)
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
