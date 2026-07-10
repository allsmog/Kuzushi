use super::canonical_run_files::ensure_canonical_run_files;
use super::run_reproducibility_metadata::summary_with_dynamic_metadata;
use super::run_paths::latest_run_path;
use super::{now_unix, run_dir, runs_root, RunSummary};
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub fn write_run_summary(target: impl AsRef<Path>, summary: &RunSummary) -> Result<PathBuf> {
    let target = target.as_ref();
    let dir = run_dir(target, &summary.run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let summary = summary_with_dynamic_metadata(target, summary);
    let summary_path = write_run_summary_file(&dir.join(run_metadata_artifact_spec().leaf), &summary)?;
    ensure_canonical_run_files(target, &summary.run_id, &summary.status)?;
    write_latest_run_id(target, &summary.run_id)?;
    Ok(summary_path)
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let path = readable_summary_path(target, run_id)?;
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let summary = parse_run_summary_body(&body, &path)?;
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
    match read_run_metadata_summary(&dir.join(run_metadata_artifact_spec().leaf)) {
        MetadataSummaryRead::Present(summary) => Some(summary),
        MetadataSummaryRead::Missing | MetadataSummaryRead::Invalid => None,
    }
}

enum MetadataSummaryRead {
    Present(RunSummary),
    Missing,
    Invalid,
}

fn read_run_metadata_summary(path: &Path) -> MetadataSummaryRead {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => read_repaired_summary(path)
            .map(MetadataSummaryRead::Present)
            .unwrap_or(MetadataSummaryRead::Invalid),
        Ok(_) => MetadataSummaryRead::Invalid,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => MetadataSummaryRead::Missing,
        Err(_) => MetadataSummaryRead::Invalid,
    }
}

fn read_repaired_summary(path: &Path) -> Option<RunSummary> {
    read_run_summary_file(path).map(|summary| repair_stale_running_summary(path, summary))
}

fn read_run_summary_file(summary_path: &Path) -> Option<RunSummary> {
    let body = fs::read_to_string(summary_path).ok()?;
    parse_run_summary_body(&body, summary_path).ok()
}

fn parse_run_summary_body(body: &str, path: &Path) -> Result<RunSummary> {
    let value: Value =
        serde_json::from_str(body).with_context(|| format!("Could not parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("Run metadata is not a JSON object: {}", path.display());
    }
    serde_json::from_value(value).map_err(|error| {
        anyhow::anyhow!(
            "Run metadata is not canonical: {error}: {}",
            path.display()
        )
    })
}

fn readable_summary_path(target: impl AsRef<Path>, run_id: &str) -> Result<PathBuf> {
    let dir = run_dir(target, run_id);
    let canonical = dir.join(run_metadata_artifact_spec().leaf);
    if readable_run_metadata_exists(&canonical, "Run metadata")? {
        return Ok(canonical);
    }
    anyhow::bail!("Run metadata is missing: {}", canonical.display())
}

fn run_metadata_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("run.json").expect("run metadata artifact must be in shared spec")
}

fn readable_run_metadata_exists(path: &Path, label: &str) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => anyhow::bail!("{label} is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn write_run_summary_file(path: &Path, summary: &RunSummary) -> Result<PathBuf> {
    reject_non_file_target(path, "Run metadata target")?;
    let body = format!("{}\n", serde_json::to_string_pretty(summary)?);
    crate::fs_atomic::write_atomic(path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path.to_path_buf())
}

fn write_latest_run_id(target: &Path, run_id: &str) -> Result<()> {
    let path = latest_run_path(target);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;
    }
    reject_non_file_target(&path, "Latest run pointer target")?;
    // The latest-run pointer is read to resolve the newest run; a torn write
    // here would desync the whole run index, so it goes through the atomic path.
    crate::fs_atomic::write_atomic(&path, &format!("{run_id}\n"))
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
        // Rewrite the repaired summary crash-safely: a torn rewrite here would
        // replace a recoverable "running" summary with a corrupt one.
        let _ = crate::fs_atomic::write_atomic(summary_path, &format!("{body}\n"));
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

#[cfg(target_os = "linux")]
fn process_is_alive(process_id: u32) -> bool {
    let proc_root = Path::new("/proc");
    if !proc_root.exists() {
        return true;
    }
    proc_root.join(process_id.to_string()).exists()
}

/// `kill(pid, 0)` probes process existence without delivering a signal:
/// `0` means alive, `EPERM` means alive but owned by another user, and
/// `ESRCH` (or any other error) means no such process.
#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_alive(process_id: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(process_id) else {
        // A pid that cannot be represented on this platform can never
        // name a live process (and would alias `kill(-1, 0)` if cast).
        return false;
    };
    if pid <= 0 {
        return false;
    }
    let probe = unsafe { libc::kill(pid, 0) };
    probe == 0 || last_errno_is_eperm()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn last_errno_is_eperm() -> bool {
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// No portable liveness probe exists here; claiming "dead" would fabricate
/// an interrupted state, so the summary is left untouched.
#[cfg(not(unix))]
fn process_is_alive(_process_id: u32) -> bool {
    true
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    #[test]
    fn current_process_is_alive() {
        assert!(process_is_alive(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn reaped_child_process_is_not_alive() {
        assert!(!process_is_alive(spawn_dead_process_id()));
    }

    #[cfg(unix)]
    #[test]
    fn running_summary_with_dead_pid_is_repaired_to_interrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = RunSummary::running("run-dead-pid", "scan", None, "target")
            .with_process_id(spawn_dead_process_id());
        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = list_run_summaries(tmp.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "interrupted");
        assert!(loaded[0].completed_at_unix.is_some());
        assert!(loaded[0].process_id.is_none());
        assert!(loaded[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no longer running"));
    }

    #[test]
    fn running_summary_with_live_pid_is_left_running() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = RunSummary::running("run-live-pid", "scan", None, "target")
            .with_process_id(std::process::id());
        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = list_run_summaries(tmp.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "running");
        assert_eq!(loaded[0].process_id, Some(std::process::id()));
    }

    /// Spawn and reap a short-lived child so its pid is known-dead.
    #[cfg(unix)]
    fn spawn_dead_process_id() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn `true`");
        let pid = child.id();
        child.wait().expect("reap child");
        pid
    }
}
