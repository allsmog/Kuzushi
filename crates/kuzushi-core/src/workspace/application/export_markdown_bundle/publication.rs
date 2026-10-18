//! Build the complete report before exposing its destination directory.
use anyhow::{Context, Result};
use std::{fs, io::ErrorKind, path::Path};

pub(in crate::workspace::application) fn publish_bundle(
    destination: &Path,
    build: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    validate_destination(destination)?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".kuzushi-report-")
        .tempdir_in(parent)
        .context("Could not prepare a private report directory")?;
    build(staging.path()).with_context(|| {
        format!(
            "Report bundle was not published at {}; retry the same destination",
            destination.display()
        )
    })?;
    install_bundle(staging.path(), destination)?;
    let _ = staging.keep();
    Ok(())
}

pub(in crate::workspace::application) fn validate_destination(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        result => result.with_context(|| format!("Could not inspect {}", path.display()))?,
    };
    anyhow::ensure!(
        metadata.is_dir(),
        "markdown-bundle export needs a directory path, not a file or symbolic link: {}",
        path.display()
    );
    let mut entries =
        fs::read_dir(path).with_context(|| format!("Could not read {}", path.display()))?;
    anyhow::ensure!(
        entries.next().transpose()?.is_none(),
        "markdown-bundle output directory must be empty: {}",
        path.display()
    );
    Ok(())
}

fn install_bundle(staging: &Path, destination: &Path) -> Result<()> {
    validate_destination(destination)?;
    let removed_empty = remove_empty_destination(destination)?;
    if let Err(error) = fs::rename(staging, destination) {
        if removed_empty {
            let _ = fs::create_dir(destination);
        }
        return Err(error).with_context(|| {
            format!(
                "Could not publish report bundle at {}",
                destination.display()
            )
        });
    }
    Ok(())
}

fn remove_empty_destination(destination: &Path) -> Result<bool> {
    match fs::remove_dir(destination) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "Could not prepare report destination {}; existing contents were preserved",
                destination.display()
            )
        }),
    }
}

#[cfg(test)]
mod tests;
