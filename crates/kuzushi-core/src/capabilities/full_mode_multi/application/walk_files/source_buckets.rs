use super::*;
use crate::capabilities::full_mode_multi::domain::{PlanningCoverage, MAX_FILE_BYTES};
use crate::workspace::InventoryPathClassification;
use anyhow::Context;
use std::path::Path;

pub(super) fn collect(
    cfg: &FullModeConfig,
    paths: Vec<String>,
    mut coverage: PlanningCoverage,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<PlannedFiles> {
    let mut files = Vec::new();
    for (index, path) in paths.into_iter().enumerate() {
        if canceled() {
            coverage.canceled = true;
            break;
        }
        progress(index + 1);
        match source_buckets(cfg, &path, index, &mut coverage, canceled) {
            Ok(buckets) => files.extend(buckets),
            Err(error) => coverage.omitted_sources.push(InventoryPathClassification {
                path,
                kind: "omitted".into(),
                reason: format!("{error:#}"),
            }),
        }
    }
    coverage.canceled |= canceled();
    Ok(PlannedFiles { files, coverage })
}

fn source_buckets(
    cfg: &FullModeConfig,
    path: &str,
    index: usize,
    coverage: &mut PlanningCoverage,
    canceled: &dyn Fn() -> bool,
) -> Result<Vec<FileBucket>> {
    anyhow::ensure!(
        index < coverage.max_source_files,
        "source file planning limit reached"
    );
    let file = crate::bounded_file::open_regular_file_within(&cfg.workspace_root, Path::new(path))?;
    let bytes =
        usize::try_from(file.metadata()?.len()).context("source size exceeds platform capacity")?;
    reserve_source_bytes(coverage, bytes)?;
    if bytes == 0 {
        return Ok(Vec::new());
    }
    if bytes <= MAX_FILE_BYTES {
        return Ok(vec![FileBucket::whole(
            path.into(),
            bytes,
            est_tokens_for_bytes(bytes),
        )]);
    }
    let (result, read) = super::source_windows::buckets(file, path, bytes, canceled);
    coverage.planning_read_bytes += read;
    result
}

fn reserve_source_bytes(coverage: &mut PlanningCoverage, bytes: usize) -> Result<()> {
    let next = coverage
        .selected_source_bytes
        .checked_add(bytes)
        .context("source size sum overflowed")?;
    anyhow::ensure!(
        next <= coverage.max_source_bytes,
        "source byte planning limit of {} reached; select a smaller explicit scope",
        coverage.max_source_bytes
    );
    coverage.selected_source_bytes = next;
    Ok(())
}
