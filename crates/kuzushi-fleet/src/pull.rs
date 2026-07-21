use crate::config::RemoteBox;
use crate::doctor::shq;
use crate::transport::Transport;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Stale runs re-pulled under today's date once re-entered triage as new
/// work; recency is therefore opt-out (`--all`), not opt-in.
pub const DEFAULT_MAX_AGE_HOURS: u64 = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PullReport {
    pub remote: String,
    pub pulled_runs: Vec<String>,
    pub inbox: String,
    pub max_age_hours: Option<u64>,
}

/// Pull recent remote run directories into the local inbox
/// (`<inbox_root>/<box>/<run>/`) and write a MANIFEST.json beside them.
/// The fleet corpus only ever ingests from the inbox — remote boxes never
/// write local aggregate state directly.
pub fn pull(
    transport: &dyn Transport,
    remote: &RemoteBox,
    inbox_root: &Path,
    max_age_hours: Option<u64>,
) -> Result<PullReport> {
    let runs = list_remote_runs(transport, remote, max_age_hours)?;
    let inbox = inbox_root.join(&remote.name);
    std::fs::create_dir_all(&inbox)
        .with_context(|| format!("Could not create inbox {}", inbox.display()))?;
    for run in &runs {
        transport.pull(
            remote,
            &format!("{}/runs/{run}", remote.workdir),
            &inbox.join(run),
        )?;
    }
    let report = PullReport {
        remote: remote.name.clone(),
        pulled_runs: runs,
        inbox: inbox.display().to_string(),
        max_age_hours,
    };
    write_manifest(&inbox, &report)?;
    Ok(report)
}

fn list_remote_runs(
    transport: &dyn Transport,
    remote: &RemoteBox,
    max_age_hours: Option<u64>,
) -> Result<Vec<String>> {
    let output = transport.run(remote, &list_runs_command(&remote.workdir, max_age_hours))?;
    Ok(parse_run_names(&output.stdout))
}

pub(crate) fn list_runs_command(workdir: &str, max_age_hours: Option<u64>) -> String {
    let recency = max_age_hours
        .map(|hours| format!(" -mmin -{}", hours * 60))
        .unwrap_or_default();
    format!(
        "find {}/runs -mindepth 1 -maxdepth 1 -type d{recency} -printf '%f\\n' 2>/dev/null || true",
        shq(workdir)
    )
}

pub(crate) fn parse_run_names(stdout: &str) -> Vec<String> {
    let mut names: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.contains('/') && !name.starts_with('.'))
        .map(str::to_string)
        .collect();
    names.sort();
    names
}

fn write_manifest(inbox: &Path, report: &PullReport) -> Result<()> {
    let path: PathBuf = inbox.join("MANIFEST.json");
    let body = serde_json::to_string_pretty(&ManifestFile {
        pulled_at_unix: now_unix(),
        report,
    })?;
    std::fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestFile<'report> {
    pulled_at_unix: u64,
    #[serde(flatten)]
    report: &'report PullReport,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recency_cutoff_is_the_default_shape_and_all_removes_it() {
        let bounded = list_runs_command("/w", Some(24));
        assert!(bounded.contains("-mmin -1440"));

        let unbounded = list_runs_command("/w", None);
        assert!(!unbounded.contains("-mmin"));
    }

    #[test]
    fn run_names_are_sanitized_and_sorted() {
        let names = parse_run_names("run-b\n\n.hidden\nnested/run\nrun-a\n");
        assert_eq!(names, vec!["run-a".to_string(), "run-b".to_string()]);
    }
}
