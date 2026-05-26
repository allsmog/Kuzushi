use std::path::{Path, PathBuf};

pub(crate) fn ui_runs_root_relative_path() -> &'static str {
    ".kuzushi/runs"
}

pub(crate) fn ui_latest_run_relative_path() -> &'static str {
    ".kuzushi/latest"
}

pub(crate) fn ui_run_artifact_relative_path(run_id: &str, leaf: &str) -> String {
    Path::new(ui_runs_root_relative_path())
        .join(run_id)
        .join(leaf)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn ui_runs_root(target: Option<&Path>) -> PathBuf {
    target
        .map(kuzushi_core::runs_root)
        .unwrap_or_else(|| PathBuf::from(ui_runs_root_relative_path()))
}

pub(crate) fn ui_run_dir(target: Option<&Path>, run_id: &str) -> PathBuf {
    target
        .map(|root| kuzushi_core::run_dir(root, run_id))
        .unwrap_or_else(|| ui_runs_root(None).join(run_id))
}

pub(crate) fn ui_latest_run_path(target: Option<&Path>) -> PathBuf {
    target
        .map(kuzushi_core::latest_run_path)
        .unwrap_or_else(|| kuzushi_core::latest_run_path(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_run_artifact_relative_path_uses_shared_runs_root_label() {
        assert_eq!(
            ui_run_artifact_relative_path("run-1", "failures.json"),
            ".kuzushi/runs/run-1/failures.json"
        );
    }

    #[test]
    fn ui_runs_root_without_target_uses_relative_label() {
        assert_eq!(
            ui_runs_root(None).to_string_lossy(),
            ui_runs_root_relative_path()
        );
    }

    #[test]
    fn ui_latest_run_without_target_uses_relative_label() {
        assert_eq!(
            ui_latest_run_path(None).to_string_lossy(),
            ui_latest_run_relative_path()
        );
    }
}
