use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn ensure_secure_child(parent: &Path, name: &str) -> Result<PathBuf> {
    let child = parent.join(name);
    ensure_secure_directory(&child)?;
    Ok(child)
}

pub(super) fn ensure_secure_directory(path: &Path) -> Result<()> {
    reject_kuzushi_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => validate_secure_directory(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_secure_directory(path)?
        }
        Err(error) => return Err(error).context("could not inspect session directory"),
    }
    set_private_directory_permissions(path)
}

pub(super) fn validate_secure_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "session directory is a symlink: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_dir(),
        "session path is not a directory: {}",
        path.display()
    );
    Ok(())
}

fn reject_kuzushi_symlink_ancestors(path: &Path) -> Result<()> {
    if !has_kuzushi_ancestor(path) {
        return Ok(());
    }
    for ancestor in path.ancestors() {
        reject_symlink(ancestor)?;
        if is_kuzushi_directory(ancestor) {
            break;
        }
    }
    Ok(())
}

fn has_kuzushi_ancestor(path: &Path) -> bool {
    path.ancestors().any(is_kuzushi_directory)
}

fn is_kuzushi_directory(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == ".kuzushi")
}

fn reject_symlink(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "session directory ancestor is a symlink: {}",
            path.display()
        );
    }
    Ok(())
}

fn create_secure_directory(path: &Path) -> Result<()> {
    let parent = path.parent().context("session directory has no parent")?;
    fs::create_dir_all(parent)?;
    let mut builder = fs::DirBuilder::new();
    configure_secure_directory(&mut builder);
    builder
        .create(path)
        .with_context(|| format!("could not create session directory {}", path.display()))
}

#[cfg(unix)]
fn configure_secure_directory(builder: &mut fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700);
}

#[cfg(not(unix))]
fn configure_secure_directory(_builder: &mut fs::DirBuilder) {}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
