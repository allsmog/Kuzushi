use super::*;
use crate::capabilities::full_mode_multi::domain::{PlanningCoverage, SKIP_DIRS};
use crate::workspace::{InventoryPathClassification, RepositoryInventory};
use anyhow::Context;
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn source_paths(
    cfg: &FullModeConfig,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<(Vec<String>, PlanningCoverage)> {
    let mut coverage = empty_coverage();
    if let Some(scope) = &cfg.scope_files {
        coverage.enumeration = "explicit-scope".into();
        return Ok((scoped_paths(cfg, scope, progress, canceled)?, coverage));
    }
    let inventory = crate::workspace::build_repository_inventory_with_observer(
        &cfg.workspace_root,
        progress,
        canceled,
    )?;
    inventory_paths(cfg, inventory, coverage, canceled())
}

pub(super) fn empty_coverage() -> PlanningCoverage {
    PlanningCoverage {
        enumeration: String::new(),
        inventory: None,
        inventory_limitation: None,
        enumeration_incomplete: false,
        excluded_paths: Vec::new(),
        omitted_sources: Vec::new(),
        selected_source_bytes: 0,
        planning_read_bytes: 0,
        max_source_bytes: crate::workspace::MAX_REPOSITORY_INSPECTED_BYTES,
        max_source_files: crate::workspace::MAX_REPOSITORY_ENTRIES,
        canceled: false,
    }
}

fn scoped_paths(
    cfg: &FullModeConfig,
    paths: &[std::path::PathBuf],
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<Vec<String>> {
    anyhow::ensure!(
        !paths.is_empty(),
        "source scope is empty; select repository files before planning work"
    );
    anyhow::ensure!(
        paths.len() <= crate::workspace::MAX_REPOSITORY_ENTRIES,
        "source scope exceeds the 100000-entry planning limit; select a smaller explicit scope"
    );
    let canonical = cfg.workspace_root.canonicalize()?;
    let mut selected = BTreeSet::new();
    for (index, path) in paths.iter().enumerate() {
        if canceled() {
            break;
        }
        progress(index + 1);
        let rel = crate::bounded_file::relative_path_within(&cfg.workspace_root, &canonical, path)
            .with_context(|| format!("invalid scoped source path {}", path.display()))?;
        crate::bounded_file::open_regular_file_within(&cfg.workspace_root, &rel)
            .with_context(|| format!("cannot inspect scoped repository file {}", path.display()))?;
        selected.insert(rel.to_string_lossy().into_owned());
    }
    Ok(selected.into_iter().collect())
}

pub(super) fn inventory_paths(
    cfg: &FullModeConfig,
    inventory: RepositoryInventory,
    mut coverage: PlanningCoverage,
    canceled: bool,
) -> Result<(Vec<String>, PlanningCoverage)> {
    let inspection = inventory
        .inspection
        .context("chunk planning requires an inventory receipt")?;
    coverage.enumeration = inspection.enumeration.clone();
    coverage.inventory_limitation = inventory.truncation.map(|limit| limit.reason);
    coverage.enumeration_incomplete = inspection.enumeration_complete != Some(true);
    coverage.canceled = canceled;
    coverage.excluded_paths = inventory.generated_vendor_paths;
    coverage
        .excluded_paths
        .extend(inspection.omitted_paths.iter().cloned());
    let extensions = extensions(cfg);
    let paths = inspection
        .files
        .iter()
        .filter_map(|path| {
            if included(path, &extensions) {
                return Some(path.clone());
            }
            coverage.excluded_paths.push(InventoryPathClassification {
                path: path.clone(),
                kind: "excluded".into(),
                reason: "outside chunk language/path selection".into(),
            });
            None
        })
        .collect();
    coverage.inventory = Some(inspection);
    Ok((paths, coverage))
}

fn extensions(cfg: &FullModeConfig) -> Vec<String> {
    if cfg.include_extensions.is_empty() {
        return c_default_extensions();
    }
    cfg.include_extensions
        .iter()
        .map(|value| value.trim_start_matches('.').to_ascii_lowercase())
        .collect()
}

fn included(path: &str, extensions: &[String]) -> bool {
    let path = Path::new(path);
    let excluded = path.iter().any(|part| {
        let name = part.to_string_lossy();
        name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref())
    });
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !excluded && extensions.contains(&ext)
}
