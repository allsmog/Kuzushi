use super::*;

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
    #[serde(skip_serializing_if = "Option::is_none")]
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
        self.artifact = Some(artifact);
        self
    }
}

pub fn append_run_event(
    target: impl AsRef<Path>,
    run_id: &str,
    event: &RunEvent,
) -> Result<PathBuf> {
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("events.jsonl");
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
    let path = run_dir(target, run_id).join("events.jsonl");
    fs::read_to_string(path)
        .map(|text| text.lines().count().saturating_add(1))
        .unwrap_or(1)
}
