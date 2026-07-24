use super::*;

pub(super) fn canonical_launcher(launcher: &Path) -> Result<PathBuf> {
    let launcher = std::fs::canonicalize(launcher)
        .with_context(|| format!("could not canonicalize {}", launcher.display()))?;
    anyhow::ensure!(
        launcher.is_file(),
        "CodeQL executable is not a regular file"
    );
    Ok(launcher)
}

pub(super) fn create_execution_snapshot(
    session: Arc<SnapshotSessionRoot>,
    launcher: &Path,
    expected: Option<&str>,
) -> Result<CodeqlExecutionSnapshot> {
    let bundle = resolve_codeql_bundle_root(launcher)?;
    let relative_launcher = launcher
        .strip_prefix(&bundle)
        .context("CodeQL launcher is outside its authenticated bundle")?;
    let directory = Arc::new(
        tempfile::Builder::new()
            .prefix("bundle-")
            .tempdir_in(session.path())?,
    );
    let revision = copy_bounded_bundle_with_durability(
        &bundle,
        directory.path(),
        CODEQL_BUNDLE_CONFIG,
        CopyDurability::Ephemeral,
    )?;
    if let Some(expected) = expected {
        anyhow::ensure!(
            revision == expected,
            "CodeQL executable bundle changed after authentication; retry the operation"
        );
    }
    let launcher = directory.path().join(relative_launcher);
    anyhow::ensure!(launcher.is_file(), "CodeQL snapshot launcher is missing");
    Ok(CodeqlExecutionSnapshot {
        launcher,
        bundle_root: directory.path().to_path_buf(),
        revision,
        cancellation: Arc::new(SnapshotCancellation::default()),
        _directory: directory,
        _session: session,
    })
}

pub(super) fn create_database_snapshot(
    session: Arc<SnapshotSessionRoot>,
    source: &Path,
    expected: &str,
) -> Result<DatabaseExecutionSnapshot> {
    let directory = Arc::new(
        tempfile::Builder::new()
            .prefix("database-")
            .tempdir_in(session.path())?,
    );
    let revision = database_identity::copy_database(source, directory.path())?;
    anyhow::ensure!(
        revision == expected,
        "CodeQL database changed while creating its execution snapshot"
    );
    Ok(DatabaseExecutionSnapshot {
        directory: directory.path().to_path_buf(),
        revision,
        cancellation: Arc::new(SnapshotCancellation::default()),
        _directory: directory,
        _session: session,
    })
}
