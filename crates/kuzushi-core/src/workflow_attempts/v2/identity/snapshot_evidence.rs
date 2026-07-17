use super::TargetContentIdentity;
use crate::run_artifacts::RunArtifactRead;
use crate::run_lifecycle::{ArtifactReference, ProjectionHealth, RunProjectionSource, SafeText};
use rusqlite::OptionalExtension;
use std::path::Path;

const SNAPSHOT_HASH_POINTERS: &[&str] = &[
    "/data/snapshot/snapshotHash",
    "/data/snapshotHash",
    "/data/provenance/snapshot/snapshotHash",
];
const TREE_HASH_POINTERS: &[&str] = &[
    "/data/snapshot/treeHash",
    "/data/treeHash",
    "/data/provenance/snapshot/treeHash",
];

pub(super) enum SnapshotEvidence {
    Absent,
    Verified(TargetContentIdentity),
    Unverified,
    Invalid,
}

struct SnapshotClaim {
    snapshot_hash: String,
    tree_hash: Option<String>,
}

pub(super) fn read_snapshot_evidence(target: &Path, run_id: &str) -> SnapshotEvidence {
    let Ok(read) = crate::run_lifecycle::load_run_projection(target, run_id) else {
        return SnapshotEvidence::Invalid;
    };
    match read.source {
        RunProjectionSource::TypedV1 => typed_snapshot_evidence(target, run_id, &read.projection),
        RunProjectionSource::Legacy => legacy_snapshot_evidence(target, run_id),
    }
}

fn typed_snapshot_evidence(
    target: &Path,
    run_id: &str,
    projection: &crate::run_lifecycle::RunProjection,
) -> SnapshotEvidence {
    if !matches!(projection.health, ProjectionHealth::Healthy) {
        return SnapshotEvidence::Invalid;
    }
    let reference = match exact_result_reference(projection) {
        Ok(Some(reference)) => reference,
        Ok(None) => return SnapshotEvidence::Absent,
        Err(()) => return SnapshotEvidence::Invalid,
    };
    let value = match crate::run_artifacts::load_correlated_run_result_value(
        target,
        run_id,
        reference.producing_item_id,
        reference,
    ) {
        Ok(value) => value,
        Err(_) => return SnapshotEvidence::Invalid,
    };
    verified_snapshot_claim(target, snapshot_claim(&value))
}

fn exact_result_reference(
    projection: &crate::run_lifecycle::RunProjection,
) -> Result<Option<&ArtifactReference>, ()> {
    let references = projection
        .call_order
        .iter()
        .filter_map(|call_id| projection.calls.get(call_id))
        .filter_map(|call| call.result_artifact.as_ref())
        .filter(|reference| reference.path.as_str() == "result.json")
        .collect::<Vec<_>>();
    match references.as_slice() {
        [] => Ok(None),
        [reference] => Ok(Some(*reference)),
        _ => Err(()),
    }
}

fn legacy_snapshot_evidence(target: &Path, run_id: &str) -> SnapshotEvidence {
    match crate::read_run_artifact_text(target, run_id, "result.json") {
        RunArtifactRead::Missing { .. } => SnapshotEvidence::Absent,
        RunArtifactRead::Ready { value, .. } => match snapshot_claim_from_body(&value) {
            Ok(None) => SnapshotEvidence::Absent,
            Ok(Some(_)) => SnapshotEvidence::Unverified,
            Err(()) => SnapshotEvidence::Invalid,
        },
        RunArtifactRead::NonFile { .. }
        | RunArtifactRead::Unsafe { .. }
        | RunArtifactRead::Unreadable { .. } => SnapshotEvidence::Invalid,
    }
}

fn snapshot_claim_from_body(body: &str) -> Result<Option<SnapshotClaim>, ()> {
    let value = serde_json::from_str::<serde_json::Value>(body).map_err(|_| ())?;
    snapshot_claim(&value)
}

fn snapshot_claim(value: &serde_json::Value) -> Result<Option<SnapshotClaim>, ()> {
    let snapshot_hash = hash_claim(value, SNAPSHOT_HASH_POINTERS);
    let tree_hash = hash_claim(value, TREE_HASH_POINTERS);
    match (snapshot_hash, tree_hash) {
        (Ok(None), Ok(None)) => Ok(None),
        (Ok(Some(snapshot_hash)), Ok(tree_hash)) => Ok(Some(SnapshotClaim {
            snapshot_hash,
            tree_hash,
        })),
        _ => Err(()),
    }
}

fn verified_snapshot_claim(
    target: &Path,
    claim: Result<Option<SnapshotClaim>, ()>,
) -> SnapshotEvidence {
    let claim = match claim {
        Ok(None) => return SnapshotEvidence::Absent,
        Ok(Some(claim)) => claim,
        Err(()) => return SnapshotEvidence::Invalid,
    };
    match indexed_snapshot_identity(target, &claim) {
        Ok(Some(identity)) => SnapshotEvidence::Verified(identity),
        Ok(None) | Err(_) => SnapshotEvidence::Invalid,
    }
}

fn indexed_snapshot_identity(
    target: &Path,
    claim: &SnapshotClaim,
) -> anyhow::Result<Option<TargetContentIdentity>> {
    let workspace = crate::workspace::WorkspaceTarget::new(target)?;
    let connection = crate::sqlite_connection::open_read_only_file(&workspace.findings_db_path())?;
    let indexed = indexed_snapshot_row(&connection, &claim.snapshot_hash)?;
    let Some((tree_hash, root_fingerprint)) = indexed else {
        return Ok(None);
    };
    let expected_root = crate::incremental_index::workspace_root_fingerprint(workspace.root());
    validate_index_claim(claim, &tree_hash, &root_fingerprint, &expected_root)?;
    verify_index_objects(&workspace, claim, &tree_hash, &expected_root)?;
    Ok(Some(TargetContentIdentity::IndexedSnapshot {
        snapshot_hash: SafeText::operator_visible(&claim.snapshot_hash),
        tree_hash: Some(SafeText::operator_visible(tree_hash)),
    }))
}

fn indexed_snapshot_row(
    connection: &rusqlite::Connection,
    snapshot_hash: &str,
) -> anyhow::Result<Option<(String, String)>> {
    connection
        .query_row(
            "select tree_hash, workspace_root_fingerprint from target_snapshots where snapshot_hash = ?1",
            [snapshot_hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(Into::into)
}

fn validate_index_claim(
    claim: &SnapshotClaim,
    tree_hash: &str,
    root_fingerprint: &str,
    expected_root: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        root_fingerprint == expected_root,
        "snapshot belongs to another target"
    );
    anyhow::ensure!(
        claim
            .tree_hash
            .as_ref()
            .is_none_or(|claim| claim == tree_hash),
        "snapshot tree claim disagrees with the indexed snapshot"
    );
    Ok(())
}

fn verify_index_objects(
    workspace: &crate::workspace::WorkspaceTarget,
    claim: &SnapshotClaim,
    tree_hash: &str,
    root_fingerprint: &str,
) -> anyhow::Result<()> {
    use crate::content_store::{object_hash, ContentStore, ObjectKind, TargetSnapshot};
    let snapshot_hash = crate::identity::Blake3Hash::new(claim.snapshot_hash.clone())?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let snapshot_bytes = store.get(&snapshot_hash)?;
    anyhow::ensure!(
        object_hash(ObjectKind::Snapshot, &snapshot_bytes) == snapshot_hash,
        "indexed snapshot object failed its content hash"
    );
    let snapshot: TargetSnapshot = serde_json::from_slice(&snapshot_bytes)?;
    anyhow::ensure!(
        snapshot.tree_hash.as_str() == tree_hash,
        "indexed snapshot object disagrees with its projected tree"
    );
    anyhow::ensure!(
        snapshot.workspace_root_fingerprint == root_fingerprint,
        "indexed snapshot object belongs to another target"
    );
    let tree_bytes = store.get(&snapshot.tree_hash)?;
    anyhow::ensure!(
        object_hash(ObjectKind::Tree, &tree_bytes) == snapshot.tree_hash,
        "indexed tree object failed its content hash"
    );
    Ok(())
}

fn hash_claim(value: &serde_json::Value, pointers: &[&str]) -> Result<Option<String>, ()> {
    let claims = pointers
        .iter()
        .filter_map(|pointer| value.pointer(pointer))
        .map(valid_hash_claim)
        .collect::<Result<Vec<_>, _>>()?;
    let Some(first) = claims.first() else {
        return Ok(None);
    };
    claims
        .iter()
        .all(|claim| claim == first)
        .then(|| first.clone())
        .ok_or(())
        .map(Some)
}

fn valid_hash_claim(value: &serde_json::Value) -> Result<String, ()> {
    let value = value.as_str().ok_or(())?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
        .ok_or(())
}
