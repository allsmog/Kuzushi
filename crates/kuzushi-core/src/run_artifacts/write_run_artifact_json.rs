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
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(RunArtifact {
        label: label.into(),
        path: path.display().to_string(),
        kind: "json".to_string(),
    })
}

pub fn append_run_trace_step(
    target: impl AsRef<Path>,
    run_id: &str,
    step: &RunTraceStep,
) -> Result<PathBuf> {
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("trace.jsonl");
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
    text.lines()
        .filter_map(|line| serde_json::from_str::<RunTraceStep>(line).ok())
        .map(|step| step.n)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
