use super::{CodeqlDatabaseProvenance, CODEQL_PROVENANCE_SCHEMA_VERSION};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn validate_current_source(
    target: &Path,
    provenance: &CodeqlDatabaseProvenance,
) -> Result<()> {
    let current = crate::remediation::patch::clean_repository_source_binding(
        target,
        crate::remediation::patch::unattended_patch_control(),
    )?;
    anyhow::ensure!(
        current.commit == provenance.source_commit && current.target_scope == provenance.target_scope,
        "managed CodeQL database was built for commit {} at scope {:?}, but the current clean source is commit {} at scope {:?}; run `codeql:create-db` again",
        provenance.source_commit,
        provenance.target_scope,
        current.commit,
        current.target_scope
    );
    Ok(())
}

pub(super) fn validate_codeql_database_provenance(
    provenance: &CodeqlDatabaseProvenance,
) -> Result<()> {
    validate_schema_version(provenance)?;
    validate_source_commit(&provenance.source_commit)?;
    crate::remediation::patch::validate_repository_target_scope(&provenance.target_scope)?;
    normalized_language(&provenance.language)?;
    uuid::Uuid::parse_str(&provenance.generation)
        .context("CodeQL provenance generation is not a UUID")?;
    Ok(())
}

fn validate_schema_version(provenance: &CodeqlDatabaseProvenance) -> Result<()> {
    anyhow::ensure!(
        provenance.schema_version == CODEQL_PROVENANCE_SCHEMA_VERSION,
        "unsupported CodeQL provenance schema version {}",
        provenance.schema_version
    );
    Ok(())
}

fn validate_source_commit(commit: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(commit.len(), 40 | 64) && commit.chars().all(|ch| ch.is_ascii_hexdigit()),
        "CodeQL provenance source commit is not a full Git object ID"
    );
    Ok(())
}

pub(super) fn normalized_language(language: &str) -> Result<String> {
    let language = language.trim().to_ascii_lowercase();
    anyhow::ensure!(
        language_is_valid(&language),
        "CodeQL provenance language is invalid"
    );
    Ok(language)
}

fn language_is_valid(language: &str) -> bool {
    !language.is_empty()
        && language
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
}

pub(super) fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => ensure_not_symlink(path, metadata).map(|()| true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn ensure_not_symlink(path: &Path, metadata: std::fs::Metadata) -> Result<()> {
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "managed CodeQL database path is a symbolic link: {}",
        path.display()
    );
    Ok(())
}

pub(super) fn reject_legacy_database(target: &Path) -> Result<()> {
    for legacy in legacy_database_paths(target) {
        reject_existing_legacy_database(&legacy)?;
    }
    Ok(())
}

fn legacy_database_paths(target: &Path) -> [std::path::PathBuf; 2] {
    [
        crate::workspace::legacy_workspace_codeql_db_path(target),
        crate::workspace::legacy_codeql_db_path(target),
    ]
}

fn reject_existing_legacy_database(path: &Path) -> Result<()> {
    if path_exists_no_follow(path)? {
        anyhow::bail!(
            "legacy CodeQL database at {} has no source provenance; rebuild it with `codeql:create-db`",
            path.display()
        );
    }
    Ok(())
}
