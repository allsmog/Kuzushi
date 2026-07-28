use super::{run_dir, run_summary_store::load_run_summary_without_repair};
use anyhow::{Context, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPruneDisposition {
    Deleted,
    WouldDelete,
    Missing,
    SkippedLive,
}

pub fn prune_run_artifacts(
    target: impl AsRef<Path>,
    run_id: &str,
    dry_run: bool,
) -> Result<RunPruneDisposition> {
    let target = target.as_ref();
    crate::run_lifecycle::RunId::parse(run_id)?;
    let directory = run_dir(target, run_id);
    if !directory.is_dir() {
        return Ok(RunPruneDisposition::Missing);
    }
    let guard = super::run_ledger::acquire_run_terminal_lock(target, run_id)?;
    let summary = load_run_summary_without_repair(target, run_id)?;
    if summary.status == "running" {
        return Ok(RunPruneDisposition::SkippedLive);
    }
    if dry_run {
        return Ok(RunPruneDisposition::WouldDelete);
    }
    drop(guard);
    std::fs::remove_dir_all(&directory)
        .with_context(|| format!("Could not delete {}", directory.display()))?;
    Ok(RunPruneDisposition::Deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_artifacts::{write_run_summary, RunSummary};

    #[test]
    fn prune_skips_a_running_run_under_the_terminal_lock() {
        let target = tempfile::tempdir().unwrap();
        let summary = RunSummary::running("run-live-prune", "tool", None, "target")
            .with_process_id(std::process::id());
        write_run_summary(target.path(), &summary).unwrap();

        assert_eq!(
            prune_run_artifacts(target.path(), &summary.run_id, false).unwrap(),
            RunPruneDisposition::SkippedLive
        );
        assert!(run_dir(target.path(), &summary.run_id).exists());
    }

    #[test]
    fn prune_deletes_only_a_terminal_run() {
        let target = tempfile::tempdir().unwrap();
        let summary = RunSummary::running("run-terminal-prune", "tool", None, "target").complete();
        write_run_summary(target.path(), &summary).unwrap();

        assert_eq!(
            prune_run_artifacts(target.path(), &summary.run_id, false).unwrap(),
            RunPruneDisposition::Deleted
        );
        assert!(!run_dir(target.path(), &summary.run_id).exists());
    }
}
