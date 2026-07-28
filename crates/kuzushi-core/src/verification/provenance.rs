mod cases;
mod reproducer;

#[allow(unused_imports)]
pub(crate) use cases::{
    EmpiricalCaseExpectation, EmpiricalCaseOracle, EmpiricalInputCase, EmpiricalInputCaseKind,
    MAX_EMPIRICAL_CASES, MAX_EMPIRICAL_CASE_BYTES, MAX_EMPIRICAL_TOTAL_BYTES,
};
#[allow(unused_imports)]
pub(crate) use reproducer::{
    load_empirical_reproducer, persist_empirical_reproducer, EmpiricalReproducerFile,
    EmpiricalReproducerSnapshot, ReproducerInvocation,
};

use crate::content_store::ObjectRef;
use crate::findings::VerificationProvenance;
use crate::incremental_index::index_workspace_snapshot;
use crate::run_lifecycle::SafeText;
use crate::workflow_attempts::TargetContentIdentity;
use crate::WorkspaceTarget;
use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn capture_verification_source_identity(
    workspace_root: &Path,
) -> Result<TargetContentIdentity> {
    let workspace = WorkspaceTarget::new(workspace_root)?;
    let indexed = index_workspace_snapshot(&workspace)
        .context("could not capture verification source snapshot")?;
    Ok(TargetContentIdentity::IndexedSnapshot {
        snapshot_hash: SafeText::operator_visible(indexed.snapshot_hash),
        tree_hash: Some(SafeText::operator_visible(indexed.tree_hash)),
    })
}

pub(crate) fn unavailable_verification_source_identity(
    error: impl std::fmt::Display,
) -> TargetContentIdentity {
    TargetContentIdentity::Unavailable {
        reason: SafeText::operator_visible(format!(
            "verification source snapshot capture failed: {error}"
        )),
    }
}

pub(crate) fn canonical_source_identity(identity: &TargetContentIdentity) -> Result<String> {
    serde_json::to_string(identity).context("could not serialize verification source identity")
}

pub(crate) fn indexed_tree_hash(identity: &TargetContentIdentity) -> Option<&str> {
    match identity {
        TargetContentIdentity::IndexedSnapshot {
            tree_hash: Some(tree_hash),
            ..
        } => Some(tree_hash.as_str()),
        _ => None,
    }
}

pub(crate) fn provenance_with_reproducer(
    source_identity: &TargetContentIdentity,
    reproducer: ObjectRef,
) -> VerificationProvenance {
    VerificationProvenance {
        source_identity: source_identity.clone(),
        reproducer: Some(reproducer),
    }
}
