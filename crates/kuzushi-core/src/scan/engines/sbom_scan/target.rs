use anyhow::Result;
use std::path::Path;

pub(super) fn ensure_directory(target: &Path) -> Result<()> {
    anyhow::ensure!(
        target.exists(),
        "sbom-scan: target does not exist: {}",
        target.display()
    );
    anyhow::ensure!(
        target.is_dir(),
        "sbom-scan: target is not a directory: {}",
        target.display()
    );
    Ok(())
}

pub(super) fn ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | "node_modules" | "target" | "vendor"))
}
