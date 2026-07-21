use super::domain::ScanRecommendation;
use super::fold::{recommend, RecommenderInputs};
use crate::findings::FindingStore;
use crate::workspace::coverage_ledger::{sweep_target, CoverageLedger, SweepReport};
use crate::workspace::{load_nested_project_scopes, ROOT_SCOPE_ID};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Gather the deterministic inputs for a target and fold them into ranked
/// scan recommendations. Read-only: a missing ledger means every scope is
/// simply unscanned; it is never created here.
pub fn recommend_scans_for_target(
    target: &Path,
    findings_store: Option<&FindingStore>,
) -> Result<Vec<ScanRecommendation>> {
    let scope_paths = scope_paths(target)?;
    let ledger = CoverageLedger::open_if_exists(target)?;
    let (latest, all) = match &ledger {
        Some(ledger) => (ledger.latest_baselines()?, ledger.all_baselines()?),
        None => (Vec::new(), Vec::new()),
    };
    let sweep = sweep_if_covered(target, &ledger);
    let surface_files = surface_files(target);
    let finding_files = finding_files(target, findings_store)?;
    Ok(recommend(&RecommenderInputs {
        scope_paths: &scope_paths,
        latest_baselines: &latest,
        all_baselines: &all,
        sweep: sweep.as_ref(),
        surface_files: &surface_files,
        finding_files: &finding_files,
    }))
}

fn scope_paths(target: &Path) -> Result<BTreeMap<String, String>> {
    let mut paths = BTreeMap::from([(ROOT_SCOPE_ID.to_string(), ".".to_string())]);
    if let Some(tree) = load_nested_project_scopes(target)? {
        for scope in tree.scopes {
            paths.insert(scope.id, scope.rel_path);
        }
    }
    Ok(paths)
}

fn sweep_if_covered(target: &Path, ledger: &Option<CoverageLedger>) -> Option<SweepReport> {
    if ledger.is_none() {
        return None;
    }
    sweep_target(target).ok()
}

/// Surface density is advisory and comes from the persisted context
/// snapshot: rebuilding it would walk the whole repository — minutes on
/// monorepo targets — and recommendations refresh inside the shell's view
/// hydration. A missing or unreadable snapshot yields an empty map, not a
/// failed recommendation run; context:build is what refreshes the density.
fn surface_files(target: &Path) -> BTreeMap<String, usize> {
    snapshot_surface_files(target).unwrap_or_default()
}

fn snapshot_surface_files(target: &Path) -> Option<BTreeMap<String, usize>> {
    let path = crate::context::context_snapshot_path(target);
    let body = crate::bounded_file::read_utf8_text_within(
        target,
        &path,
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    )
    .ok()?;
    let snapshot: serde_json::Value = serde_json::from_str(&body).ok()?;
    let summary = snapshot.pointer("/attackSurfaceMap/summary")?.clone();
    let summary: crate::workspace::AttackSurfaceSummary = serde_json::from_value(summary).ok()?;
    Some(summary.by_file)
}

fn finding_files(
    target: &Path,
    findings_store: Option<&FindingStore>,
) -> Result<BTreeSet<String>> {
    let Some(store) = findings_store else {
        return Ok(BTreeSet::new());
    };
    let findings = store.list_all_findings()?;
    Ok(findings
        .iter()
        .map(|finding| target_relative(&finding.file_path, target))
        .collect())
}

fn target_relative(file_path: &str, target: &Path) -> String {
    Path::new(file_path)
        .strip_prefix(target)
        .map(|relative| relative.to_string_lossy().into_owned())
        .unwrap_or_else(|_| file_path.to_string())
}

#[cfg(test)]
mod surface_source_tests {
    use super::*;

    /// Surface density must come from the persisted snapshot — never from a
    /// live repository walk, which blocks view refresh for minutes on
    /// monorepo targets.
    #[test]
    fn surface_files_read_the_persisted_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            crate::context::context_snapshot_path(temp.path()),
            r#"{"attackSurfaceMap":{"summary":{"total":2,"byKind":{},"byFile":{"src/a.rs":2}}}}"#,
        )
        .unwrap();

        let files = surface_files(temp.path());

        assert_eq!(files, BTreeMap::from([("src/a.rs".to_string(), 2)]));
    }

    #[test]
    fn missing_snapshot_yields_empty_advisory_density() {
        let temp = tempfile::tempdir().unwrap();

        assert!(surface_files(temp.path()).is_empty());
    }
}
