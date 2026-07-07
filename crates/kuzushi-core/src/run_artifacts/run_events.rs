use super::*;
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunEvent {
    pub n: usize,
    pub kind: String,
    pub status: String,
    pub message: String,
    pub at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<RunArtifact>,
}

impl RunEvent {
    pub fn new(
        n: usize,
        kind: impl Into<String>,
        status: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            n,
            kind: kind.into(),
            status: status.into(),
            message: message.into(),
            at_unix: now_unix(),
            tool: None,
            artifact: None,
        }
    }

    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    pub fn with_artifact(mut self, artifact: RunArtifact) -> Self {
        self.artifact = artifact.normalized();
        self
    }
}

pub fn append_run_event(
    target: impl AsRef<Path>,
    run_id: &str,
    event: &RunEvent,
) -> Result<PathBuf> {
    let dir = run_dir(&target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = run_artifact_path(&target, run_id, run_events_spec().leaf);
    reject_non_file_event_target(&path)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(event)?)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn next_run_event_number(target: impl AsRef<Path>, run_id: &str) -> usize {
    let path = run_artifact_path(target, run_id, run_events_spec().leaf);
    let Ok(text) = fs::read_to_string(path) else {
        return 1;
    };
    crate::run_artifacts::jsonl_numbering::next_jsonl_number::<RunEvent>(&text, |event| event.n)
}

fn run_events_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("events.jsonl").expect("run events artifact must be in shared spec")
}

fn reject_non_file_event_target(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("Run event log target is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}
