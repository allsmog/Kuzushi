use super::*;
use crate::findings::{CapturedFindingSources, FindingSourceSnapshot};
use crate::scan::domain::NativeSourceBindingReceipt;

const MAX_RETAINED_SOURCE_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct NativeFindingSource {
    snapshot: FindingSourceSnapshot,
    tree_hash: String,
    snapshot_hash: String,
}

impl NativeFindingSource {
    pub(super) fn capture(
        workspace: &WorkspaceTarget,
        store: &FindingStore,
        cancellation: &ScanCancellation,
        expected: Option<&crate::workspace::source_snapshot::SourceSnapshot>,
    ) -> Result<Self> {
        let (snapshot_hash, tree_hash) = source_identity(workspace, cancellation, expected)?;
        let snapshot =
            store.prepare_finding_source_snapshot(workspace.root(), &snapshot_hash, &tree_hash)?;
        Ok(Self {
            snapshot,
            tree_hash,
            snapshot_hash,
        })
    }

    pub(super) fn persist(
        &self,
        workspace: &WorkspaceTarget,
        store: &FindingStore,
        run_id: &str,
        output: &mut ScanEngineOutputs,
        cancellation: &ScanCancellation,
    ) -> Result<()> {
        let captured = match self.capture_current(workspace, &output.findings, cancellation) {
            Ok(source) => {
                output.coverage.source_binding = Some(self.receipt(Some(&source), None));
                Some(source)
            }
            Err(error) => {
                output.coverage.source_binding =
                    Some(self.receipt(None, Some(format!("{error:#}"))));
                None
            }
        };
        for finding in &output.findings {
            persist_finding(store, run_id, finding, captured.as_ref())?;
        }
        Ok(())
    }

    fn receipt(
        &self,
        captured: Option<&CapturedFindingSources>,
        limitation: Option<String>,
    ) -> NativeSourceBindingReceipt {
        let (captured_files, captured_bytes) =
            captured.map_or((0, 0), CapturedFindingSources::captured_counts);
        NativeSourceBindingReceipt {
            snapshot_hash: self.snapshot_hash.clone(),
            tree_hash: self.tree_hash.clone(),
            authenticated: captured.is_some(),
            captured_files,
            captured_bytes,
            max_capture_bytes: MAX_RETAINED_SOURCE_BYTES,
            limitation,
        }
    }

    fn capture_current(
        &self,
        workspace: &WorkspaceTarget,
        findings: &[Finding],
        cancellation: &ScanCancellation,
    ) -> Result<CapturedFindingSources> {
        let current = crate::incremental_index::current_workspace_tree_hash_cancellable(
            workspace.root(),
            &mut |_| {},
            &|| cancellation.is_cancelled(),
        )?;
        anyhow::ensure!(current == self.tree_hash, "Source changed during native scan; retained observations have no authenticated snapshot binding");
        self.snapshot
            .capture_native(findings, MAX_RETAINED_SOURCE_BYTES, &|| {
                cancellation.is_cancelled()
            })
    }
}

fn source_identity(
    workspace: &WorkspaceTarget,
    cancellation: &ScanCancellation,
    expected: Option<&crate::workspace::source_snapshot::SourceSnapshot>,
) -> Result<(String, String)> {
    if let Some(source) = expected {
        let (snapshot, tree) = source.hashes();
        return Ok((snapshot.into(), tree.into()));
    }
    let source = crate::incremental_index::register_workspace_tree_identity_cancellable(
        workspace,
        &mut |_| {},
        &|| cancellation.is_cancelled(),
    )?;
    Ok((source.snapshot_hash, source.tree_hash))
}

fn persist_finding(
    store: &FindingStore,
    run_id: &str,
    finding: &Finding,
    source: Option<&CapturedFindingSources>,
) -> Result<i64> {
    match source {
        Some(source) => store.insert_finding_with_sources(run_id, finding, source),
        None => store.insert_unbound_native_finding(run_id, finding),
    }
}

#[cfg(test)]
mod tests;
