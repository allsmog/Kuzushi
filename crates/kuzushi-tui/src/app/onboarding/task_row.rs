use super::task_id::PlanningTaskId;
use std::path::{Path, PathBuf};

/// Per-row state shown in the planning picker. Built once at picker open
/// and refreshed when artifacts change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningTaskRow {
    pub id: PlanningTaskId,
    pub label: &'static str,
    pub tool_name: &'static str,
    pub artifact_path: PathBuf,
    pub artifact_state: ArtifactState,
    pub model_backed: bool,
    pub required_cli: Option<&'static str>,
    pub cli_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Cached,
    Invalid,
    Missing,
}

impl ArtifactState {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactState::Cached => "cached",
            ArtifactState::Invalid => "invalid",
            ArtifactState::Missing => "missing",
        }
    }
}

impl PlanningTaskRow {
    pub fn for_task(task: PlanningTaskId, target: &Path) -> Self {
        let artifact_path = target.join(task.artifact_relative_path());
        let artifact_state = artifact_state(&artifact_path);
        let required_cli = task.required_cli();
        let cli_available = required_cli
            .map(cli_is_on_path)
            .unwrap_or(true);
        Self {
            id: task,
            label: task.label(),
            tool_name: task.tool_name(),
            artifact_path,
            artifact_state,
            model_backed: task.is_model_backed(),
            required_cli,
            cli_available,
        }
    }

    /// Whether this row should be pre-checked when the picker first opens.
    /// A row is pre-checked when its artifact is missing or invalid AND
    /// its required CLI binary (if any) is available.
    pub fn pre_checked(&self) -> bool {
        self.cli_available
            && !matches!(self.artifact_state, ArtifactState::Cached)
            && !forced_off_by_default(self.id)
    }

    /// One-line hint shown next to the row (cost + missing dep info).
    pub fn cost_hint(&self) -> String {
        let base = if self.model_backed {
            "model-backed"
        } else {
            "no model cost"
        };
        match self.required_cli {
            Some(cli) if !self.cli_available => {
                format!("{base} (requires {cli} — not on PATH)")
            }
            Some(cli) => format!("{base} (requires {cli})"),
            None => base.to_string(),
        }
    }
}

/// PASTA is opt-in even when its artifact is missing — STRIDE is the
/// default methodology and we don't want to spend two LLM passes by
/// default.
fn forced_off_by_default(task: PlanningTaskId) -> bool {
    matches!(task, PlanningTaskId::BuildPastaThreatModel)
}

pub fn artifact_state(path: &Path) -> ArtifactState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => directory_artifact_state(path),
        Ok(metadata) if metadata.is_file() => file_artifact_state(path),
        Ok(_) => ArtifactState::Invalid,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ArtifactState::Missing,
        Err(_) => ArtifactState::Invalid,
    }
}

fn directory_artifact_state(path: &Path) -> ArtifactState {
    match std::fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                ArtifactState::Cached
            } else {
                ArtifactState::Missing
            }
        }
        Err(_) => ArtifactState::Invalid,
    }
}

fn file_artifact_state(path: &Path) -> ArtifactState {
    let Ok(body) = std::fs::read_to_string(path) else {
        return ArtifactState::Invalid;
    };
    if body.trim().is_empty() {
        return ArtifactState::Invalid;
    }
    // JSON artifacts must parse; other artifacts (Markdown, binary CPG)
    // are deemed cached on presence.
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        if serde_json::from_str::<serde_json::Value>(&body).is_ok() {
            ArtifactState::Cached
        } else {
            ArtifactState::Invalid
        }
    } else {
        ArtifactState::Cached
    }
}

pub fn cli_is_on_path(name: &str) -> bool {
    if let Some(env_var) = cli_env_override(name) {
        if let Some(value) = std::env::var_os(env_var) {
            if std::path::Path::new(&value).is_file() {
                return true;
            }
        }
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
}

fn cli_env_override(name: &str) -> Option<&'static str> {
    match name {
        "joern-parse" => Some("KUZUSHI_JOERN_BIN"),
        "codeql" => Some("KUZUSHI_CODEQL_BIN"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_artifact_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            artifact_state(&tmp.path().join("nope.json")),
            ArtifactState::Missing
        );
    }

    #[test]
    fn empty_directory_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("empty");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(artifact_state(&dir), ArtifactState::Missing);
    }

    #[test]
    fn populated_directory_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("populated");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "x").unwrap();
        assert_eq!(artifact_state(&dir), ArtifactState::Cached);
    }

    #[test]
    fn valid_json_file_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{}").unwrap();
        assert_eq!(artifact_state(&path), ArtifactState::Cached);
    }

    #[test]
    fn malformed_json_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.json");
        std::fs::write(&path, "{not-json").unwrap();
        assert_eq!(artifact_state(&path), ArtifactState::Invalid);
    }

    #[test]
    fn pasta_defaults_off_even_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let row = PlanningTaskRow::for_task(PlanningTaskId::BuildPastaThreatModel, tmp.path());
        assert!(!row.pre_checked());
    }
}
