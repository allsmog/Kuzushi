use super::*;
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};
use crate::run_lifecycle::{RunItemEnvelopeV1, RunItemV1};
use std::collections::BTreeSet;
use std::io::Write;

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
    /// Privacy-preserving audit metadata for an interactive operator question.
    /// Free-form answer text is deliberately never stored; callers may only
    /// record whether free-form input was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<RunInteractionAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunInteractionAudit {
    pub request_id: String,
    pub question_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predefined_label: Option<String>,
    pub resolution: String,
    pub freeform_supplied: bool,
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
            interaction: None,
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

    pub fn with_interaction(mut self, interaction: RunInteractionAudit) -> Self {
        self.interaction = Some(interaction);
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

pub(crate) fn append_compat_run_item_events(
    target: &Path,
    run_id: &str,
    items: &[RunItemEnvelopeV1],
) -> Result<()> {
    let candidates = items
        .iter()
        .filter_map(|item| compat_run_item_event(target, run_id, item))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(());
    }
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    let path = checked_run_artifact_path(target, run_id, run_events_spec().leaf)?;
    reject_non_file_event_target(&path)?;
    let existing = read_compat_event_state(&path)?;
    append_compat_event_batch(&path, candidates, existing)
}

fn read_compat_event_state(path: &Path) -> Result<(usize, BTreeSet<String>)> {
    let text = match crate::bounded_file::read_utf8_text(
        path,
        super::run_artifact_reader::MAX_RUN_ARTIFACT_READ_BYTES as usize,
    ) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("read compatibility run events"),
    };
    let read = parse_run_event_lines(&text);
    let markers = read
        .events
        .iter()
        .map(|event| event.message.clone())
        .collect();
    Ok((
        read.events.iter().map(|event| event.n).max().unwrap_or(0) + 1,
        markers,
    ))
}

fn append_compat_event_batch(
    path: &Path,
    candidates: Vec<RunEvent>,
    (mut next, existing): (usize, BTreeSet<String>),
) -> Result<()> {
    let mut bytes = Vec::new();
    for mut event in candidates {
        if existing.contains(&event.message) {
            continue;
        }
        event.n = next;
        next = next.saturating_add(1);
        serde_json::to_writer(&mut bytes, &event)?;
        bytes.push(b'\n');
    }
    if bytes.is_empty() {
        return Ok(());
    }
    let mut file = open_compat_append_file(path)?;
    file.write_all(&bytes)
        .context("append compatibility run events")?;
    file.sync_data().context("sync compatibility run events")
}

fn compat_run_item_event(
    target: &Path,
    run_id: &str,
    item: &RunItemEnvelopeV1,
) -> Option<RunEvent> {
    let marker = format!("[typed:{}]", item.event_hash);
    let (kind, status, label, tool) = match &item.item {
        RunItemV1::TerminalOutcome { status, .. } => {
            terminal_compat_fields(target, run_id, *status)
        }
        other => compat_event_fields(other)?,
    };
    let mut event = RunEvent::new(0, kind, status, format!("{label} {marker}"));
    event.at_unix = item.occurred_at_ms / 1_000;
    if let Some(tool) = tool {
        event = event.with_tool(tool);
    }
    Some(event)
}

fn terminal_compat_fields(
    target: &Path,
    run_id: &str,
    status: crate::run_lifecycle::RunItemStatus,
) -> (&'static str, String, String, Option<String>) {
    let summary = super::load_run_summary(target, run_id).ok();
    let kind = match summary.as_ref().map(|summary| summary.kind.as_str()) {
        Some("scan") => "scan",
        Some("agent") => "shell",
        _ => "tool",
    };
    (
        kind,
        status.label().into(),
        "terminal result recorded".into(),
        summary.and_then(|summary| summary.tool),
    )
}

fn compat_event_fields(item: &RunItemV1) -> Option<(&'static str, String, String, Option<String>)> {
    match item {
        RunItemV1::PlanUpdated { .. } | RunItemV1::TaskUpdated { .. } => {
            compat_work_event_fields(item)
        }
        RunItemV1::ToolCallRequested { .. }
        | RunItemV1::ToolCallRejected { .. }
        | RunItemV1::ToolCallStarted { .. }
        | RunItemV1::ToolCallFinished { .. } => compat_call_event_fields(item),
        RunItemV1::ArtifactProduced { .. }
        | RunItemV1::FindingDelta { .. }
        | RunItemV1::OperatorQuestion { .. }
        | RunItemV1::OperatorDecision { .. }
        | RunItemV1::PhaseReceipt { .. } => compat_domain_event_fields(item),
        RunItemV1::TerminalOutcome { .. } => unreachable!("terminal events use run metadata"),
        _ => None,
    }
}

fn compat_work_event_fields(
    item: &RunItemV1,
) -> Option<(&'static str, String, String, Option<String>)> {
    match item {
        RunItemV1::PlanUpdated { status, .. } => {
            Some(("plan", status.label().into(), "plan updated".into(), None))
        }
        RunItemV1::TaskUpdated { status, title, .. } => Some((
            "task",
            status.label().into(),
            "task updated".into(),
            Some(title.to_string()),
        )),
        _ => None,
    }
}

fn compat_call_event_fields(
    item: &RunItemV1,
) -> Option<(&'static str, String, String, Option<String>)> {
    match item {
        RunItemV1::ToolCallRequested { tool_name, .. } => Some((
            "tool",
            "requested".into(),
            "tool requested".into(),
            Some(tool_name.to_string()),
        )),
        RunItemV1::ToolCallRejected { .. } => {
            Some(("tool", "skipped".into(), "tool rejected".into(), None))
        }
        RunItemV1::ToolCallStarted { tool_name, .. } => Some((
            "tool",
            "started".into(),
            "tool started".into(),
            Some(tool_name.to_string()),
        )),
        RunItemV1::ToolCallFinished { status, .. } => {
            Some(("tool", status.label().into(), "tool finished".into(), None))
        }
        _ => None,
    }
}

fn compat_domain_event_fields(
    item: &RunItemV1,
) -> Option<(&'static str, String, String, Option<String>)> {
    match item {
        RunItemV1::ArtifactProduced { .. } => Some((
            "artifact",
            "completed".into(),
            "artifact produced".into(),
            None,
        )),
        RunItemV1::FindingDelta { .. } => Some((
            "finding",
            "completed".into(),
            "finding store changed".into(),
            None,
        )),
        RunItemV1::OperatorQuestion { .. } => Some((
            "interaction",
            "waiting".into(),
            "operator question opened".into(),
            None,
        )),
        RunItemV1::OperatorDecision { .. } => Some((
            "interaction",
            "resolved".into(),
            "operator question resolved".into(),
            None,
        )),
        RunItemV1::PhaseReceipt { status, .. } => Some((
            "receipt",
            status.label().into(),
            "phase receipt committed".into(),
            None,
        )),
        _ => None,
    }
}

#[cfg(unix)]
fn open_compat_append_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_compat_append_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
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
                .with_context(|| format!("Could not read run event log {}", path.display()));
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
