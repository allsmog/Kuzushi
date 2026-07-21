use super::*;
use anyhow::Result;
use kuzushi_core::{
    sorted_finding_alias_indices, FindingStore, PatchAttemptSummary, PatchLifecycleRecord,
};
use std::path::Path;

pub(crate) fn open_finding_store_for_target_read_only(
    target: Option<&PathBuf>,
) -> Result<(WorkspaceTarget, FindingStore)> {
    let workspace = workspace_for_target(target)?;
    let path = workspace.findings_db_path();
    let store = if path.exists() {
        FindingStore::open_read_only(path)?
    } else {
        FindingStore::open(path)?
    };
    Ok((workspace, store))
}

pub(crate) fn finding_by_reference_for_target(
    target: Option<&PathBuf>,
    reference: &str,
) -> Result<Option<Finding>> {
    let (_, store) = open_finding_store_for_target_read_only(target)?;
    store.get_finding_by_reference(reference)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingPatchTruth {
    pub(crate) latest_result: Option<PatchAttemptSummary>,
    pub(crate) lifecycle: Option<PatchLifecycleRecord>,
    pub(crate) lifecycle_matches_finding_generation: bool,
}

pub(crate) fn finding_patch_truth_for_target(
    target: &Path,
    fingerprint: &str,
    finding_scan_id: Option<&str>,
) -> Result<Option<FindingPatchTruth>> {
    let Some(store) = open_existing_finding_store_read_only(target)? else {
        return Ok(None);
    };
    let latest_result = store.latest_patch_attempt_summary_for_finding(fingerprint)?;
    let lifecycle = store.latest_patch_lifecycle_for_finding(fingerprint)?;
    let lifecycle_matches_finding_generation = lifecycle
        .as_ref()
        .is_none_or(|record| record.finding_scan_id.as_deref() == finding_scan_id);
    Ok(Some(FindingPatchTruth {
        latest_result,
        lifecycle,
        lifecycle_matches_finding_generation,
    }))
}

fn open_existing_finding_store_read_only(target: &Path) -> Result<Option<FindingStore>> {
    let workspace = WorkspaceTarget::new(target)?;
    let path = workspace.findings_db_path();
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => anyhow::bail!("findings DB path is not a regular file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    Ok(Some(FindingStore::open_read_only(path)?))
}

/// Scanned-time source context for a finding, sliced from the observation
/// blob that stored the whole cited file at insert time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannedSnippetWindow {
    pub(crate) start_line: usize,
    pub(crate) focus_line: usize,
    pub(crate) lines: Vec<String>,
}

pub(crate) fn scanned_snippet_for_target(
    target: &Path,
    stable_fp: &str,
    scan_id: Option<&str>,
    focus_line: u32,
) -> Result<Option<ScannedSnippetWindow>> {
    let Some(store) = open_existing_finding_store_read_only(target)? else {
        return Ok(None);
    };
    let Some(source) = store.latest_observation_source(stable_fp, scan_id)? else {
        return Ok(None);
    };
    let Some(bytes) = store.read_observation_blob(&source.blob_hash)? else {
        return Ok(None);
    };
    let focus_line = source
        .display_line
        .and_then(|line| usize::try_from(line).ok())
        .filter(|line| *line > 0)
        .unwrap_or(focus_line.max(1) as usize);
    Ok(Some(scanned_snippet_window(&bytes, focus_line)))
}

fn scanned_snippet_window(bytes: &[u8], focus_line: usize) -> ScannedSnippetWindow {
    let text = String::from_utf8_lossy(bytes);
    let lines = text.lines().collect::<Vec<_>>();
    let start_line = focus_line
        .saturating_sub(crate::ui_view_models::SNIPPET_CONTEXT_BEFORE)
        .max(1);
    let end_line = focus_line
        .saturating_add(crate::ui_view_models::SNIPPET_CONTEXT_AFTER)
        .min(lines.len().max(1));
    let window = lines
        .iter()
        .skip(start_line - 1)
        .take(end_line.saturating_sub(start_line - 1))
        .map(|line| line.to_string())
        .collect();
    ScannedSnippetWindow {
        start_line,
        focus_line,
        lines: window,
    }
}

impl ShellApp {
    pub(crate) fn invalidate_finding_patch_truth(&mut self, fingerprint: Option<&str>) {
        self.invalidate_view_hydration();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_finding_patch_truth(fingerprint);
    }
}

pub(crate) fn load_finding_completion_values(target: &Path) -> Vec<String> {
    finding_completion_values(
        load_findings_for_target(Some(&target.to_path_buf()), 200).unwrap_or_default(),
    )
}

pub(crate) fn finding_completion_values_from_findings(findings: &[Finding]) -> Vec<String> {
    finding_completion_values(findings.to_vec())
}

fn load_findings_for_target(target: Option<&PathBuf>, limit: usize) -> Result<Vec<Finding>> {
    let (_, store) = open_finding_store_for_target_read_only(target)?;
    store.list_findings(limit)
}

fn finding_completion_values(findings: Vec<Finding>) -> Vec<String> {
    let mut values = Vec::new();
    for (alias, index) in sorted_finding_alias_indices(&findings) {
        let Some(finding) = findings.get(index) else {
            continue;
        };
        values.push(alias);
        values.push(short_fingerprint(&finding.fingerprint));
        values.push(finding.fingerprint.clone());
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_patch_truth_does_not_initialize_workspace_state() {
        let target = tempfile::tempdir().unwrap();

        let truth = finding_patch_truth_for_target(target.path(), "missing", None).unwrap();

        assert!(truth.is_none());
        assert!(!target.path().join(".kuzushi").exists());
    }
}
