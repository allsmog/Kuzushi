use super::{
    operator_home_for_target, CodeqlDatabaseProvenance, DatabaseIdentity,
    MAX_CODEQL_PROVENANCE_BYTES,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CODEQL_RECEIPT_SCHEMA_VERSION: u32 = 1;
const CODEQL_RECEIPTS_DIR: &str = "codeql-receipts";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodeqlPromotionReceipt {
    schema_version: u32,
    target_id: String,
    database_identity: String,
    provenance: CodeqlDatabaseProvenance,
}

pub(super) fn write_codeql_promotion_receipt(
    target: &Path,
    provenance: &CodeqlDatabaseProvenance,
    database_identity: &DatabaseIdentity,
) -> Result<()> {
    let operator_home = operator_home_for_target(target)?;
    write_codeql_promotion_receipt_at(&operator_home, target, provenance, database_identity)
}

pub(super) fn write_codeql_promotion_receipt_at(
    operator_home: &Path,
    target: &Path,
    provenance: &CodeqlDatabaseProvenance,
    database_identity: &DatabaseIdentity,
) -> Result<()> {
    let target_id = target_id(target)?;
    let path = prepare_receipt_path(operator_home, target, &target_id)?;
    let receipt = CodeqlPromotionReceipt {
        schema_version: CODEQL_RECEIPT_SCHEMA_VERSION,
        target_id,
        database_identity: database_identity.as_str().to_string(),
        provenance: provenance.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    crate::fs_atomic::write_atomic_bytes(&path, &bytes)
        .context("could not write operator CodeQL promotion receipt")
}

pub(super) fn verify_codeql_promotion_receipt(
    target: &Path,
    database: &Path,
    provenance: &CodeqlDatabaseProvenance,
) -> Result<DatabaseIdentity> {
    let operator_home = operator_home_for_target(target)?;
    let expected_target_id = target_id(target)?;
    let path = receipt_path(&operator_home, target, &expected_target_id)?;
    let receipt = read_promotion_receipt(&operator_home, &path)?;
    validate_promotion_receipt(database, provenance, &expected_target_id, &receipt)?;
    Ok(DatabaseIdentity::from_receipt(receipt.database_identity))
}

fn read_promotion_receipt(operator_home: &Path, path: &Path) -> Result<CodeqlPromotionReceipt> {
    let raw = crate::bounded_file::read_utf8_text_within(
        operator_home,
        path,
        MAX_CODEQL_PROVENANCE_BYTES,
    )
    .with_context(|| {
        format!(
            "managed CodeQL database has no operator promotion receipt at {}; run `codeql:create-db` again",
            path.display()
        )
    })?;
    serde_json::from_str(&raw)
        .context("operator CodeQL promotion receipt is malformed; run `codeql:create-db` again")
}

fn validate_promotion_receipt(
    database: &Path,
    provenance: &CodeqlDatabaseProvenance,
    expected_target_id: &str,
    receipt: &CodeqlPromotionReceipt,
) -> Result<()> {
    let actual_identity = super::super::promotion::database_identity(database)?;
    anyhow::ensure!(
        receipt.schema_version == CODEQL_RECEIPT_SCHEMA_VERSION
            && receipt.target_id == expected_target_id
            && receipt.provenance == *provenance
            && receipt.database_identity == actual_identity.as_str(),
        "managed CodeQL database does not match its operator promotion receipt; run `codeql:create-db` again"
    );
    Ok(())
}

fn prepare_receipt_path(operator_home: &Path, target: &Path, target_id: &str) -> Result<PathBuf> {
    let path = receipt_path(operator_home, target, target_id)?;
    crate::workspace::initialize_workspace_state(operator_home)?;
    let directory = receipt_relative_dir();
    crate::workspace::ensure_workspace_descendant_dir(operator_home, &directory)?;
    Ok(path)
}

pub(super) fn receipt_path(
    operator_home: &Path,
    target: &Path,
    target_id: &str,
) -> Result<PathBuf> {
    let operator_home = std::fs::canonicalize(operator_home)
        .context("could not resolve operator home for CodeQL receipt")?;
    let target = std::fs::canonicalize(target).context("could not resolve CodeQL target")?;
    ensure_receipt_store_separate(&operator_home, &target)?;
    crate::workspace::validated_workspace_descendant(
        &operator_home,
        receipt_relative_dir().join(format!("{target_id}.json")),
    )
}

fn ensure_receipt_store_separate(operator_home: &Path, target: &Path) -> Result<()> {
    let receipt_store = operator_home.join(receipt_relative_dir());
    anyhow::ensure!(
        !receipt_store.starts_with(target) && !target.starts_with(&receipt_store),
        "CodeQL target overlaps the operator-owned receipt store"
    );
    Ok(())
}

pub(super) fn receipt_relative_dir() -> PathBuf {
    PathBuf::from(crate::workspace::KUZUSHI_STATE_DIR)
        .join(crate::workspace::WORKSPACE_STATE_VERSION_DIR)
        .join(CODEQL_RECEIPTS_DIR)
}

fn target_id(target: &Path) -> Result<String> {
    let target = std::fs::canonicalize(target).context("could not resolve CodeQL target")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-target-v1\0");
    hash_path(&mut hasher, &target);
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(unix)]
fn hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    hasher.update(path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    for unit in path.as_os_str().encode_wide() {
        hasher.update(&unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    hasher.update(path.to_string_lossy().as_bytes());
}
