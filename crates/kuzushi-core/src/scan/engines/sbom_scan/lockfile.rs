use super::bounded_fs as fs;
use super::target::ignored_dir;
use super::*;

pub(super) fn collect_lockfiles(
    target: &Path,
    cancellation: &ScanCancellation,
) -> Result<Vec<SbomLockfile>> {
    let mut lockfiles = Vec::new();
    collect_lockfiles_in(target, target, &mut lockfiles, cancellation)?;
    lockfiles.sort_by_key(|lockfile| lockfile.path.clone());
    Ok(lockfiles)
}

fn collect_lockfiles_in(
    target: &Path,
    dir: &Path,
    lockfiles: &mut Vec<SbomLockfile>,
    cancellation: &ScanCancellation,
) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("sbom-scan scan cancelled");
    }
    for entry in fs::read_dir(dir).with_context(|| format!("sbom-scan: read {}", dir.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() && !ignored_dir(&path) {
            collect_lockfiles_in(target, &path, lockfiles, cancellation)?;
        } else if file_type.is_file() && is_lockfile(&path) {
            lockfiles.push(lockfile_digest(target, &path)?);
        }
    }
    Ok(())
}

fn is_lockfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "Cargo.lock"
                    | "package-lock.json"
                    | "npm-shrinkwrap.json"
                    | "pnpm-lock.yaml"
                    | "yarn.lock"
                    | "poetry.lock"
                    | "Pipfile.lock"
                    | "uv.lock"
                    | "go.sum"
                    | "composer.lock"
                    | "Gemfile.lock"
                    | "packages.lock.json"
                    | "Package.resolved"
                    | "gradle.lockfile"
                    | "pubspec.lock"
                    | "renv.lock"
                    | "Podfile.lock"
                    | "Chart.lock"
                    | "Cartfile.resolved"
                    | "deno.lock"
                    | "mix.lock"
                    | "bun.lock"
                    | "bun.lockb"
            )
        })
}

fn lockfile_digest(target: &Path, path: &Path) -> Result<SbomLockfile> {
    let bytes = fs::read(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    Ok(SbomLockfile {
        path: relative_display(target, path),
        sha256: format!(
            "sha256:{}",
            kuzushi_mcp_common::cache::sha256_hex_bytes(&bytes)
        ),
    })
}
