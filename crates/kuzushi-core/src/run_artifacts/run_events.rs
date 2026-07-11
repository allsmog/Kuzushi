use super::*;
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct RunEventRead {
    pub events: Vec<RunEvent>,
    pub malformed_lines: usize,
}

pub fn load_run_events(target: impl AsRef<Path>, run_id: &str) -> Result<RunEventRead> {
    let body = super::run_artifact_reader::read_run_artifact_text_or_empty(
        target,
        run_id,
        run_events_spec().leaf,
        "Run event log",
    )?;
    Ok(parse_run_event_lines(&body))
}

fn parse_run_event_lines(body: &str) -> RunEventRead {
    let mut read = RunEventRead {
        events: Vec::new(),
        malformed_lines: 0,
    };
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<RunEvent>(line) {
            Ok(event) => read.events.push(event),
            Err(_) => read.malformed_lines += 1,
        }
    }
    read
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
    let target = target.as_ref();
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    let path = checked_run_artifact_path(target, run_id, run_events_spec().leaf)?;
    reject_non_file_event_target(&path)?;
    let mut numbered = event.clone();
    numbered.n = next_event_number_from_path(&path)?;
    let mut line = serde_json::to_string(&numbered)?;
    line.push('\n');
    super::jsonl_append::append_jsonl_line(&path, &line)?;
    Ok(path)
}

pub fn next_run_event_number(target: impl AsRef<Path>, run_id: &str) -> usize {
    checked_run_artifact_path(target, run_id, run_events_spec().leaf)
        .and_then(|path| next_event_number_from_path(&path))
        .unwrap_or(1)
}

fn next_event_number_from_path(path: &Path) -> Result<usize> {
    let text = match crate::bounded_file::read_utf8_text(
        path,
        super::run_artifact_reader::MAX_RUN_ARTIFACT_READ_BYTES as usize,
    ) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Could not read run event log {}", path.display()))
        }
    };
    Ok(crate::run_artifacts::jsonl_numbering::next_jsonl_number::<
        RunEvent,
    >(&text, |event| event.n))
}

fn run_events_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("events.jsonl").expect("run events artifact must be in shared spec")
}

fn reject_non_file_event_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Run event log target must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("Run event log target is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}
