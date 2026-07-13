use super::{GitContext, GENERATED_PROBES, TRACKABLE_PROBES};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

impl GitContext {
    pub(super) fn policy_inputs(&self, root: &Path) -> Result<Vec<PathBuf>> {
        anyhow::ensure!(
            root.starts_with(&self.repository_root),
            "Workspace {} is outside Git root {}",
            root.display(),
            self.repository_root.display()
        );
        let mut paths = git_marker_paths_through(root, &self.repository_root);
        paths.extend(ignore_paths_through(root, &self.repository_root));
        paths.extend(probe_ignore_paths(root));
        paths.extend([
            self.git_dir.join("config"),
            self.git_dir.join("config.worktree"),
            self.git_dir.join("HEAD"),
            self.common_dir.join("config"),
            self.info_exclude.clone(),
        ]);
        paths.extend(self.config_inputs.iter().cloned());
        paths.extend(global_config_paths());
        if let Some(path) = &self.configured_global_exclude {
            paths.push(path.clone());
        } else if let Some(path) = default_global_exclude_path() {
            paths.push(path);
        }
        policy_paths_with_resolved_targets(paths)
    }
}

fn policy_paths_with_resolved_targets(mut paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    for path in paths.clone() {
        match std::fs::canonicalize(&path) {
            Ok(resolved) => paths.push(resolved),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Could not resolve Git policy input {}", path.display())
                })
            }
        }
    }
    Ok(paths)
}

pub(super) fn git_marker_paths(root: &Path) -> Vec<PathBuf> {
    root.ancestors().map(|path| path.join(".git")).collect()
}

fn git_marker_paths_through(root: &Path, repository_root: &Path) -> Vec<PathBuf> {
    ancestors_through(root, repository_root)
        .into_iter()
        .map(|path| path.join(".git"))
        .collect()
}

fn ignore_paths_through(root: &Path, repository_root: &Path) -> Vec<PathBuf> {
    ancestors_through(root, repository_root)
        .into_iter()
        .map(|path| path.join(".gitignore"))
        .collect()
}

fn probe_ignore_paths(root: &Path) -> Vec<PathBuf> {
    GENERATED_PROBES
        .iter()
        .chain(TRACKABLE_PROBES)
        .flat_map(|probe| ignore_paths_for_probe(root, probe))
        .collect()
}

fn ignore_paths_for_probe(root: &Path, probe: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut directory = root.join(probe).parent().map(Path::to_path_buf);
    while let Some(current) = directory {
        paths.push(current.join(".gitignore"));
        if current == root {
            break;
        }
        directory = current.parent().map(Path::to_path_buf);
    }
    paths
}

fn ancestors_through(root: &Path, boundary: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for path in root.ancestors() {
        paths.push(path.to_path_buf());
        if path == boundary {
            break;
        }
    }
    paths
}

fn global_config_paths() -> Vec<PathBuf> {
    let mut paths = user_config_paths();
    paths.push(system_config_path());
    paths
}

fn user_config_paths() -> Vec<PathBuf> {
    if let Some(path) = std::env::var_os("GIT_CONFIG_GLOBAL") {
        return vec![PathBuf::from(path)];
    }
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".gitconfig"));
    }
    if let Some(config) = default_config_home() {
        paths.push(config.join("git/config"));
    }
    paths
}

fn system_config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("GIT_CONFIG_SYSTEM") {
        PathBuf::from(path)
    } else {
        PathBuf::from("/etc/gitconfig")
    }
}

fn default_global_exclude_path() -> Option<PathBuf> {
    default_config_home().map(|config| config.join("git/ignore"))
}

fn default_config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
}
