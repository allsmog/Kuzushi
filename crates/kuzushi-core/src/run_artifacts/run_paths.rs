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

pub fn kuzushi_root(target: impl AsRef<Path>) -> PathBuf {
    target.as_ref().join(".kuzushi")
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
