use super::bounded_fs as fs;
use super::SbomInputs;
use super::*;
use anyhow::Context;

pub(super) fn collect_lockfiles(
    target: &SbomInputs,
    files: &[PathBuf],
) -> Result<Vec<SbomLockfile>> {
    files
        .iter()
        .filter(|path| is_lockfile(path))
        .map(|path| lockfile_digest(target, path))
        .collect()
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

fn lockfile_digest(target: &SbomInputs, path: &Path) -> Result<SbomLockfile> {
    let bytes =
        fs::read(target, path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    Ok(SbomLockfile {
        path: relative_display(target, path),
        sha256: format!(
            "sha256:{}",
            kuzushi_mcp_common::cache::sha256_hex_bytes(&bytes)
        ),
    })
}
