use super::{run_dir, runs_root, RunSummary};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn write_run_summary(target: impl AsRef<Path>, summary: &RunSummary) -> Result<PathBuf> {
    let dir = run_dir(target, &summary.run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("summary.json");
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(summary)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let path = run_dir(target, run_id).join("summary.json");
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("Could not parse {}", path.display()))
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
    read_run_summary_file(&entry.path().join("summary.json"))
}

fn is_directory_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_type()
        .map(|file_type| file_type.is_dir())
        .unwrap_or(false)
}

fn read_run_summary_file(summary_path: &Path) -> Option<RunSummary> {
    let body = fs::read_to_string(summary_path).ok()?;
    serde_json::from_str::<RunSummary>(&body).ok()
}

fn sort_run_summaries(summaries: &mut [RunSummary]) {
    summaries.sort_by(|left, right| right.run_id.cmp(&left.run_id));
}
