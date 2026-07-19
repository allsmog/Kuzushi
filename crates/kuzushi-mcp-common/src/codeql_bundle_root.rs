use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn resolve_codeql_bundle_root(launcher: &Path) -> Result<PathBuf> {
    let launcher = fs::canonicalize(launcher)
        .with_context(|| format!("could not resolve CodeQL launcher {}", launcher.display()))?;
    anyhow::ensure!(launcher.is_file(), "CodeQL launcher is not a regular file");
    let parent = launcher.parent().context("CodeQL launcher has no parent")?;
    let root = if is_bin_directory(parent) {
        parent
            .parent()
            .context("CodeQL bin directory has no bundle parent")?
    } else {
        parent
    };
    ensure_dedicated_bundle_root(root)?;
    fs::canonicalize(root).context("could not canonicalize CodeQL bundle root")
}

fn is_bin_directory(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("bin"))
}

fn ensure_dedicated_bundle_root(root: &Path) -> Result<()> {
    anyhow::ensure!(
        !is_broad_sensitive_root(root),
        "CodeQL bundle root {} is too broad or sensitive; install CodeQL in a dedicated bundle directory",
        root.display()
    );
    Ok(())
}

fn is_broad_sensitive_root(path: &Path) -> bool {
    if path.parent().is_none() || dirs::home_dir().is_some_and(|home| path == home) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_launcher_selects_its_dedicated_parent_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("codeql-bundle");
        let launcher = bundle.join("bin/codeql");
        fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        fs::write(&launcher, "launcher").unwrap();

        assert_eq!(
            resolve_codeql_bundle_root(&launcher).unwrap(),
            fs::canonicalize(bundle).unwrap()
        );
    }

    #[test]
    fn broad_bundle_roots_are_rejected() {
        let error = ensure_dedicated_bundle_root(Path::new("/usr/local"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("too broad or sensitive"), "{error}");
    }
}
