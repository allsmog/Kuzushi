use super::{fs, Context, Path, PathBuf, RepositorySourceBinding, Result};
use std::io::Read;

mod bundle;

pub(super) use bundle::*;

const MAX_LAUNCHER_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn canonical_launcher(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("could not resolve CodeQL launcher {}", path.display()))?;
    let metadata = fs::metadata(&canonical)?;
    anyhow::ensure!(metadata.is_file(), "CodeQL launcher is not a regular file");
    anyhow::ensure!(
        metadata.len() <= MAX_LAUNCHER_BYTES,
        "CodeQL launcher exceeds the {} byte identity limit",
        MAX_LAUNCHER_BYTES
    );
    Ok(canonical)
}

pub(super) fn launcher_digest(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("could not open CodeQL launcher {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn validate_external_bundle_root(
    bundle_root: &Path,
    repository_root: &Path,
) -> Result<()> {
    anyhow::ensure!(
        !bundle_root.starts_with(repository_root) && !repository_root.starts_with(bundle_root),
        "CodeQL external bundle root {} overlaps the live repository {}; install CodeQL in a dedicated directory outside the repository",
        bundle_root.display(),
        repository_root.display()
    );
    anyhow::ensure!(
        !is_broad_sensitive_root(bundle_root),
        "CodeQL external bundle root {} is too broad or sensitive; install CodeQL in a dedicated bundle directory",
        bundle_root.display()
    );
    Ok(())
}

fn is_broad_sensitive_root(path: &Path) -> bool {
    if path.parent().is_none()
        || dirs::home_dir().is_some_and(|home| path == home)
        || path.file_name().is_some_and(|name| name == "bin")
    {
        return true;
    }
    [
        "/Applications",
        "/Library",
        "/System",
        "/Users",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/opt",
        "/private/tmp",
        "/tmp",
        "/usr",
        "/usr/local",
        "/var",
    ]
    .into_iter()
    .any(|sensitive| path == Path::new(sensitive))
}

pub(super) fn repository_root(
    target_root: &Path,
    source_binding: &RepositorySourceBinding,
) -> Result<PathBuf> {
    let target_root = fs::canonicalize(target_root)?;
    let mut root = target_root.clone();
    if source_binding.target_scope != "." {
        for _ in Path::new(&source_binding.target_scope).components() {
            anyhow::ensure!(root.pop(), "repository target scope escaped its root");
        }
    }
    let rebound = if source_binding.target_scope == "." {
        root.clone()
    } else {
        root.join(&source_binding.target_scope)
    };
    anyhow::ensure!(
        fs::canonicalize(rebound)? == target_root,
        "repository target scope does not match the prepared source root"
    );
    Ok(root)
}

pub(super) fn verify_launcher_identity(path: &Path, expected_digest: &str) -> Result<()> {
    let canonical = canonical_launcher(path)?;
    anyhow::ensure!(
        canonical == path && launcher_digest(&canonical)? == expected_digest,
        "CodeQL launcher content changed after preparation; prepare and authorize the operation again"
    );
    Ok(())
}
