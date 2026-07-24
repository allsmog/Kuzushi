use super::promotion::{codeql_database_has_shape, DatabaseIdentity};
use crate::remediation::patch::RepositorySourceBinding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod receipts;
mod validation;

#[cfg(test)]
mod tests;

use receipts::verify_codeql_promotion_receipt;
use validation::{
    normalized_language, path_exists_no_follow, reject_legacy_database,
    validate_codeql_database_provenance, validate_current_source,
};

#[cfg(test)]
pub(crate) use tests::write_test_codeql_database_provenance;

pub(super) const CODEQL_PROVENANCE_FILE: &str = ".kuzushi-provenance.json";
const CODEQL_PROVENANCE_SCHEMA_VERSION: u32 = 1;
pub(super) const MAX_CODEQL_PROVENANCE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CodeqlDatabaseProvenance {
    schema_version: u32,
    pub(crate) source_commit: String,
    pub(crate) target_scope: String,
    pub(crate) language: String,
    pub(crate) generation: String,
}

pub(crate) struct ValidatedManagedCodeqlDatabase {
    path: PathBuf,
    pub(crate) provenance: CodeqlDatabaseProvenance,
    expected_identity: DatabaseIdentity,
    _destination_lock: crate::file_lock::ExclusiveFileLock,
}

impl std::fmt::Debug for ValidatedManagedCodeqlDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedManagedCodeqlDatabase")
            .field("path", &self.path)
            .field("provenance", &self.provenance)
            .field("expected_identity", &self.expected_identity)
            .finish_non_exhaustive()
    }
}

impl ValidatedManagedCodeqlDatabase {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn database_identity(&self) -> &str {
        self.expected_identity.as_str()
    }

    pub(crate) fn run_verified<T>(&self, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
        let result = operation(&self.path);
        self.verify_unchanged()?;
        result
    }

    fn verify_unchanged(&self) -> Result<()> {
        let actual = super::promotion::database_identity(&self.path)?;
        anyhow::ensure!(
            actual == self.expected_identity,
            "managed CodeQL database changed while in use; discard its output and run `codeql:create-db` again"
        );
        Ok(())
    }
}

pub(super) fn write_codeql_database_provenance(
    database: &Path,
    binding: &RepositorySourceBinding,
    language: &str,
) -> Result<CodeqlDatabaseProvenance> {
    let provenance = new_provenance(binding, language)?;
    let bytes = serde_json::to_vec_pretty(&provenance)?;
    crate::fs_atomic::write_atomic_bytes(&database.join(CODEQL_PROVENANCE_FILE), &bytes)
        .context("could not write CodeQL database provenance")?;
    Ok(provenance)
}

pub(super) fn write_codeql_promotion_receipt(
    target: &Path,
    provenance: &CodeqlDatabaseProvenance,
    database_identity: &DatabaseIdentity,
) -> Result<()> {
    receipts::write_codeql_promotion_receipt(target, provenance, database_identity)
}

fn new_provenance(
    binding: &RepositorySourceBinding,
    language: &str,
) -> Result<CodeqlDatabaseProvenance> {
    let provenance = CodeqlDatabaseProvenance {
        schema_version: CODEQL_PROVENANCE_SCHEMA_VERSION,
        source_commit: binding.commit.clone(),
        target_scope: binding.target_scope.clone(),
        language: normalized_language(language)?,
        generation: uuid::Uuid::new_v4().to_string(),
    };
    validate_codeql_database_provenance(&provenance)?;
    Ok(provenance)
}

pub(super) fn read_codeql_database_provenance(database: &Path) -> Result<CodeqlDatabaseProvenance> {
    let path = database.join(CODEQL_PROVENANCE_FILE);
    let raw =
        crate::bounded_file::read_utf8_text_within(database, &path, MAX_CODEQL_PROVENANCE_BYTES)
            .with_context(|| format!("could not read CodeQL provenance {}", path.display()))?;
    let provenance: CodeqlDatabaseProvenance = serde_json::from_str(&raw)
        .with_context(|| format!("invalid CodeQL provenance {}", path.display()))?;
    validate_codeql_database_provenance(&provenance)?;
    Ok(provenance)
}

pub(crate) fn resolve_managed_codeql_database(
    target: &Path,
) -> Result<Option<ValidatedManagedCodeqlDatabase>> {
    let path = crate::workspace::workspace_codeql_db_path(target);
    if !path_exists_no_follow(&path)? {
        reject_legacy_database(target)?;
        return Ok(None);
    }
    resolve_existing_managed_database(target, path).map(Some)
}

fn resolve_existing_managed_database(
    target: &Path,
    path: PathBuf,
) -> Result<ValidatedManagedCodeqlDatabase> {
    let destination_lock = super::acquire_managed_database_lock(target, &path)?;
    ensure_database_shape(&path)?;
    let provenance = read_trusted_provenance(&path)?;
    validate_current_source(target, &provenance)?;
    let expected_identity = verify_codeql_promotion_receipt(target, &path, &provenance)?;
    Ok(ValidatedManagedCodeqlDatabase {
        path,
        provenance,
        expected_identity,
        _destination_lock: destination_lock,
    })
}

fn ensure_database_shape(path: &Path) -> Result<()> {
    anyhow::ensure!(
        codeql_database_has_shape(path),
        "managed CodeQL database at {} is incomplete or unsafe; run `codeql:create-db` again",
        path.display()
    );
    Ok(())
}

fn read_trusted_provenance(path: &Path) -> Result<CodeqlDatabaseProvenance> {
    read_codeql_database_provenance(path).with_context(|| {
        format!(
            "managed CodeQL database at {} has no trusted provenance; run `codeql:create-db` again",
            path.display()
        )
    })
}

#[cfg(not(test))]
fn operator_home_for_target(_target: &Path) -> Result<PathBuf> {
    dirs::home_dir().context("could not resolve operator home for CodeQL promotion receipt")
}

#[cfg(test)]
fn operator_home_for_target(target: &Path) -> Result<PathBuf> {
    Ok(tests::test_operator_home(target)
        .unwrap_or_else(|| tests::register_test_operator_home(target)))
}
