use crate::capabilities::full_mode_multi::domain::{FileBucket, FullModeConfig, BYTES_PER_TOKEN};
use anyhow::Result;

mod inventory;
mod source_buckets;
mod source_windows;
#[cfg(test)]
mod tests;

pub(super) struct PlannedFiles {
    pub files: Vec<FileBucket>,
    pub coverage: crate::capabilities::full_mode_multi::domain::PlanningCoverage,
}

pub(super) fn walk_files(
    cfg: &FullModeConfig,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<PlannedFiles> {
    let (paths, coverage) = inventory::source_paths(cfg, progress, canceled)?;
    source_buckets::collect(cfg, paths, coverage, progress, canceled)
}

pub(crate) fn c_default_extensions() -> Vec<String> {
    ["c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub(crate) fn est_tokens_for_bytes(bytes: usize) -> usize {
    ((bytes as f64) / BYTES_PER_TOKEN).ceil() as usize
}
