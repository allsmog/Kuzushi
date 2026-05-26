use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn new_run_id(prefix: &str) -> String {
    let prefix = sanitize_run_id_prefix(prefix);
    let prefix = if prefix.is_empty() {
        "run"
    } else {
        prefix.as_str()
    };
    let suffix = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}-{}", now_unix(), &suffix[..12])
}

pub fn runs_root(target: impl AsRef<Path>) -> PathBuf {
    kuzushi_root(target).join("runs")
}

pub fn run_dir(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    runs_root(target).join(run_id)
}

pub fn run_artifact_path(target: impl AsRef<Path>, run_id: &str, leaf: impl AsRef<Path>) -> PathBuf {
    run_dir(target, run_id).join(leaf)
}

pub fn kuzushi_root(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(target)
}

pub fn latest_run_path(target: impl AsRef<Path>) -> PathBuf {
    kuzushi_root(target).join("latest")
}

fn sanitize_run_id_prefix(prefix: &str) -> String {
    prefix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_artifact_paths_use_workspace_state_root() {
        let target = Path::new("/repo");

        assert_eq!(kuzushi_root(target), crate::workspace::workspace_state_root(target));
        assert_eq!(runs_root(target), crate::workspace::workspace_state_root(target).join("runs"));
        assert_eq!(
            latest_run_path(target),
            crate::workspace::workspace_state_root(target).join("latest")
        );
        assert_eq!(
            run_artifact_path(target, "run-123", "failures.json"),
            crate::workspace::workspace_state_root(target)
                .join("runs")
                .join("run-123")
                .join("failures.json")
        );
    }
}
