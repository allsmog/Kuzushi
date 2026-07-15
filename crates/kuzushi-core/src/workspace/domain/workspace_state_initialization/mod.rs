use super::*;
use std::io::Write;

mod descendant_policy;
mod git_policy;
mod local_policy;
mod proof_cache;
#[cfg(test)]
mod tests;

const IGNORE_FILE: &str = ".gitignore";
const MAX_IGNORE_POLICY_BYTES: usize = 64 * 1024;
const DEFAULT_IGNORE_POLICY: &[u8] =
    b"*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";

pub(crate) fn initialize_workspace_state(root: &Path) -> Result<PathBuf> {
    let state_root = ensure_workspace_descendant_dir(root, KUZUSHI_STATE_DIR)?;
    let root = state_root.parent().with_context(|| {
        format!(
            "Workspace state root has no parent: {}",
            state_root.display()
        )
    })?;
    let ignore_path = state_root.join(IGNORE_FILE);
    let policy = load_or_create_policy(root, &ignore_path)?;
    ensure_policy_is_verified(root, &ignore_path, &policy)?;
    ensure_workspace_descendant_dir(
        root,
        Path::new(KUZUSHI_STATE_DIR).join(WORKSPACE_STATE_VERSION_DIR),
    )
}

fn ensure_policy_is_verified(root: &Path, ignore_path: &Path, policy: &[u8]) -> Result<()> {
    retry_policy_verification(|| verify_policy_once(root, ignore_path, policy))
}

fn retry_policy_verification<T>(mut verify: impl FnMut() -> Result<T>) -> Result<T> {
    match verify() {
        Ok(value) => Ok(value),
        Err(first_error) => verify().with_context(|| {
            format!("Workspace policy verification changed during its first attempt: {first_error:#}")
        }),
    }
}

fn verify_policy_once(root: &Path, ignore_path: &Path, policy: &[u8]) -> Result<()> {
    descendant_policy::validate(root)?;
    if proof_cache::is_current(root, policy)? {
        return descendant_policy::validate(root);
    }
    local_policy::validate_local_policy(policy)?;
    let snapshot = git_policy::validate_effective_policy(root)?;
    let current = read_existing_policy(root, ignore_path)?;
    anyhow::ensure!(
        current == policy,
        "Workspace state ignore policy changed while Kuzushi was validating it; retry"
    );
    descendant_policy::validate(root)?;
    anyhow::ensure!(
        proof_cache::remember_if_current(root, policy, snapshot)?,
        "Workspace ignore inputs changed while Kuzushi was validating them; retry"
    );
    Ok(())
}

fn load_or_create_policy(root: &Path, path: &Path) -> Result<Vec<u8>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_existing_policy(root, path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_default_policy(root, path)
        }
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn read_existing_policy(root: &Path, path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Could not inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Workspace state ignore policy must be a no-follow regular file: {}",
        path.display()
    );
    crate::bounded_file::read_regular_bytes_within(root, path, MAX_IGNORE_POLICY_BYTES)
        .with_context(|| {
            format!(
                "Workspace state ignore policy must be a no-follow regular file: {}",
                path.display()
            )
        })
}

fn create_default_policy(root: &Path, path: &Path) -> Result<Vec<u8>> {
    let temporary_path = temporary_policy_path(path);
    let mut file = create_new_ignore_file(&temporary_path)
        .with_context(|| format!("Could not create {}", temporary_path.display()))?;
    file.write_all(DEFAULT_IGNORE_POLICY)
        .with_context(|| format!("Could not write {}", temporary_path.display()))?;
    file.sync_all()
        .with_context(|| format!("Could not sync {}", temporary_path.display()))?;
    publish_default_policy(&temporary_path, path)?;
    crate::fs_atomic::sync_parent_dir(path)
        .with_context(|| format!("Could not sync parent of {}", path.display()))?;
    read_existing_policy(root, path)
}

fn temporary_policy_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".gitignore.kuzushi-init-{}",
        uuid::Uuid::new_v4().simple()
    ))
}

fn publish_default_policy(temporary_path: &Path, path: &Path) -> Result<()> {
    let install = fs::hard_link(temporary_path, path);
    let cleanup = fs::remove_file(temporary_path);
    cleanup.with_context(|| format!("Could not remove {}", temporary_path.display()))?;
    match install {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not create {}", path.display())),
    }
}

#[cfg(unix)]
fn create_new_ignore_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_ignore_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
}
