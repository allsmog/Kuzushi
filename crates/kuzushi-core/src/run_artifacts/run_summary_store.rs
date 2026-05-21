use super::canonical_run_files::ensure_canonical_run_files;
use super::run_reproducibility_metadata::summary_with_dynamic_metadata;
use super::run_paths::latest_run_path;
use super::{now_unix, run_dir, runs_root, RunSummary};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const LEGACY_SUMMARY_FILE: &str = "summary.json";
const RUN_METADATA_FILE: &str = "run.json";

pub fn write_run_summary(target: impl AsRef<Path>, summary: &RunSummary) -> Result<PathBuf> {
    let target = target.as_ref();
    let dir = run_dir(target, &summary.run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let summary = summary_with_dynamic_metadata(target, summary);
    let summary_path = write_run_summary_file(&dir.join(LEGACY_SUMMARY_FILE), &summary)?;
    write_run_summary_file(&dir.join(RUN_METADATA_FILE), &summary)?;
    ensure_canonical_run_files(target, &summary.run_id, &summary.status)?;
    write_latest_run_id(target, &summary.run_id)?;
    Ok(summary_path)
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let path = readable_summary_path(target, run_id);
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let summary: RunSummary = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(repair_stale_running_summary(&path, summary))
}

pub fn list_run_summaries(target: impl AsRef<Path>) -> Result<Vec<RunSummary>> {
    let root = runs_root(target);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut summaries = collect_run_summaries(&root)?;
    sort_run_summaries(&mut summaries);
    Ok(summaries)
}

pub(crate) fn collect_run_summaries(root: &Path) -> Result<Vec<RunSummary>> {
    let mut summaries = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("Could not read {}", root.display()))? {
        let entry = entry?;
        if let Some(summary) = read_run_summary_entry(&entry) {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}

pub(crate) fn read_run_summary_entry(entry: &fs::DirEntry) -> Option<RunSummary> {
    if !is_directory_entry(entry) {
        return None;
    }
    read_run_metadata_entry(&entry.path())
}

fn is_directory_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_type()
        .map(|file_type| file_type.is_dir())
        .unwrap_or(false)
}

fn read_run_metadata_entry(dir: &Path) -> Option<RunSummary> {
    read_repaired_summary(&dir.join(RUN_METADATA_FILE))
        .or_else(|| read_repaired_summary(&dir.join(LEGACY_SUMMARY_FILE)))
}

fn read_repaired_summary(path: &Path) -> Option<RunSummary> {
    read_run_summary_file(path).map(|summary| repair_stale_running_summary(path, summary))
}

fn read_run_summary_file(summary_path: &Path) -> Option<RunSummary> {
    let body = fs::read_to_string(summary_path).ok()?;
    serde_json::from_str::<RunSummary>(&body).ok()
}

fn readable_summary_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    let dir = run_dir(target, run_id);
    let canonical = dir.join(RUN_METADATA_FILE);
    canonical
        .exists()
        .then_some(canonical)
        .unwrap_or_else(|| dir.join(LEGACY_SUMMARY_FILE))
}

fn write_run_summary_file(path: &Path, summary: &RunSummary) -> Result<PathBuf> {
    reject_non_file_target(path, "Run metadata target")?;
    let body = format!("{}\n", serde_json::to_string_pretty(summary)?);
    fs::write(path, body).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path.to_path_buf())
}

fn write_latest_run_id(target: &Path, run_id: &str) -> Result<()> {
    let path = latest_run_path(target);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;
    }
    reject_non_file_target(&path, "Latest run pointer target")?;
    fs::write(&path, format!("{run_id}\n"))
        .with_context(|| format!("Could not write {}", path.display()))
}

fn reject_non_file_target(path: &Path, label: &str) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("{label} is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn sort_run_summaries(summaries: &mut [RunSummary]) {
    summaries.sort_by(|left, right| right.run_id.cmp(&left.run_id));
}

fn repair_stale_running_summary(summary_path: &Path, summary: RunSummary) -> RunSummary {
    let Some(process_id) = summary.process_id else {
        return summary;
    };
    if summary.status != "running" || process_is_alive(process_id) {
        return summary;
    }
    let repaired = interrupted_summary(summary, process_id);
    if let Ok(body) = serde_json::to_string_pretty(&repaired) {
        let _ = fs::write(summary_path, format!("{body}\n"));
    }
    repaired
}

fn interrupted_summary(mut summary: RunSummary, process_id: u32) -> RunSummary {
    summary.status = "interrupted".to_string();
    summary.completed_at_unix = Some(now_unix());
    summary.error = Some(format!(
        "run process {process_id} is no longer running; marking summary interrupted"
    ));
    summary.process_id = None;
    summary
}

fn process_is_alive(process_id: u32) -> bool {
    let proc_root = Path::new("/proc");
    if !proc_root.exists() {
        return true;
    }
    proc_root.join(process_id.to_string()).exists()
}
