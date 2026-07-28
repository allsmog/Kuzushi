use crate::findings::{
    PatchDetectorReplayOutcome, PatchLifecycleRecord, PatchLifecycleState,
    PatchReverificationFileHash, PatchReverificationReceipt,
};
use crate::remediation::patch::hash_optional_file;
use anyhow::Result;
use std::path::Path;

pub(crate) fn empirical_detector_state(
    ladder_state: Option<PatchLifecycleState>,
    detector_outcome: PatchDetectorReplayOutcome,
) -> PatchLifecycleState {
    if let Some(state) = ladder_state {
        return state;
    }
    match detector_outcome {
        PatchDetectorReplayOutcome::NotRediscovered => PatchLifecycleState::Verified,
        PatchDetectorReplayOutcome::Rediscovered => PatchLifecycleState::StillVulnerable,
        PatchDetectorReplayOutcome::Failed | PatchDetectorReplayOutcome::NotRun => {
            PatchLifecycleState::Failed
        }
    }
}

pub(crate) fn active_touched_hashes(
    target: &Path,
    record: &PatchLifecycleRecord,
) -> Result<Vec<PatchReverificationFileHash>> {
    record
        .touched_files
        .iter()
        .map(|file| {
            Ok(PatchReverificationFileHash {
                path: file.path.clone(),
                hash: hash_optional_file(target, Path::new(&file.path))?,
            })
        })
        .collect()
}

pub(crate) fn persist_receipt(
    target: &Path,
    receipt: &PatchReverificationReceipt,
) -> Result<crate::content_store::ObjectRef> {
    receipt.validate()?;
    let workspace = crate::workspace::WorkspaceTarget::new(target)?;
    crate::content_store::ContentStore::open(workspace.objects_dir())?
        .put_json(crate::content_store::ObjectKind::ProofSnapshot, receipt)
}
