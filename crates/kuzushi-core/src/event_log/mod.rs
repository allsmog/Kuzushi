use crate::identity::{hash_parts, Blake3Hash};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVENT_LOG_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENT_LOG_LINE_BYTES: usize = 1024 * 1024;
const MAX_EVENT_LOG_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVENT_LOG_EVENTS: usize = 1_000_000;
const MAX_EVENT_LOG_SEGMENTS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    RunStarted,
    RunCompleted,
    RunFailed,
    SnapshotIndexed,
    FileIndexed,
    FileDeleted,
    AttackSurfaceIndexed,
    FindingObserved,
    FindingDisappeared,
    FindingReopened,
    FindingRekeyed,
    TriageDecided,
    SuppressionAdded,
    SuppressionExpired,
    SuppressionRemoved,
    VerificationRecorded,
    PatchAttemptRecorded,
    PatchLifecycleRecorded,
    ModelCallRecorded,
    PluginInvocationRecorded,
    DiagnosticRecorded,
    ProjectionCheckpointed,
    CompactionCompleted,
    /// A reviewer opened a finding for substantive review. Recorded before any
    /// verdict exists, so a later decision — or its absence — can be read
    /// against what was knowable at the moment review began.
    ReviewSessionStarted,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunStarted => "run-started",
            Self::RunCompleted => "run-completed",
            Self::RunFailed => "run-failed",
            Self::SnapshotIndexed => "snapshot-indexed",
            Self::FileIndexed => "file-indexed",
            Self::FileDeleted => "file-deleted",
            Self::AttackSurfaceIndexed => "attack-surface-indexed",
            Self::FindingObserved => "finding-observed",
            Self::FindingDisappeared => "finding-disappeared",
            Self::FindingReopened => "finding-reopened",
            Self::FindingRekeyed => "finding-rekeyed",
            Self::TriageDecided => "triage-decided",
            Self::SuppressionAdded => "suppression-added",
            Self::SuppressionExpired => "suppression-expired",
            Self::SuppressionRemoved => "suppression-removed",
            Self::VerificationRecorded => "verification-recorded",
            Self::PatchAttemptRecorded => "patch-attempt-recorded",
            Self::PatchLifecycleRecorded => "patch-lifecycle-recorded",
            Self::ModelCallRecorded => "model-call-recorded",
            Self::PluginInvocationRecorded => "plugin-invocation-recorded",
            Self::DiagnosticRecorded => "diagnostic-recorded",
            Self::ProjectionCheckpointed => "projection-checkpointed",
            Self::CompactionCompleted => "compaction-completed",
            Self::ReviewSessionStarted => "review-session-started",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    pub seq: u64,
    pub event_hash: Blake3Hash,
    pub prev_event_hash: Option<Blake3Hash>,
    pub event_kind: EventKind,
    pub actor: String,
    pub run_id: Option<String>,
    pub target_snapshot: Option<Blake3Hash>,
    pub created_at: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct EventLog {
    root: PathBuf,
    head: RefCell<Option<Option<EventEnvelope>>>,
}

impl EventLog {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        fs::create_dir_all(root).with_context(|| format!("Could not create {}", root.display()))?;
        ensure_log_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            head: RefCell::new(None),
        })
    }

    pub(crate) fn append(
        &self,
        event_kind: EventKind,
        actor: impl Into<String>,
        run_id: Option<String>,
        target_snapshot: Option<Blake3Hash>,
        payload: Value,
    ) -> Result<EventEnvelope> {
        let head = self.head()?;
        let seq = head.as_ref().map(|event| event.seq + 1).unwrap_or(1);
        let prev_event_hash = head.map(|event| event.event_hash);
        let created_at = now_isoish();
        let actor = actor.into();
        let event_hash = event_hash(
            seq,
            prev_event_hash.as_ref(),
            event_kind,
            &actor,
            run_id.as_deref(),
            target_snapshot.as_ref(),
            &created_at,
            &payload,
        )?;
        let envelope = EventEnvelope {
            seq,
            event_hash,
            prev_event_hash,
            event_kind,
            actor,
            run_id,
            target_snapshot,
            created_at,
            payload,
        };
        self.append_envelope(&envelope)?;
        *self.head.borrow_mut() = Some(Some(envelope.clone()));
        Ok(envelope)
    }

    pub fn read_all(&self) -> Result<Vec<EventEnvelope>> {
        let mut events = Vec::new();
        let segments = self.segment_files()?;
        let last_index = segments.len().saturating_sub(1);
        for (position, (_, path)) in segments.iter().enumerate() {
            let remaining = MAX_EVENT_LOG_EVENTS.saturating_sub(events.len());
            // Only the active (last) segment may carry a torn tail from a
            // process killed mid-append; earlier segments must be pristine.
            let segment = read_segment_events(path, remaining, position == last_index)?;
            anyhow::ensure!(
                segment.len() <= remaining,
                "Event log exceeds the {MAX_EVENT_LOG_EVENTS}-event aggregate limit"
            );
            events.extend(segment);
        }
        Ok(events)
    }

    pub fn verify_chain(&self) -> Result<()> {
        let events = self.read_all()?;
        let mut expected_prev = None;
        let mut expected_seq = 1;
        for event in &events {
            verify_event_in_chain(event, expected_seq, expected_prev.as_ref())?;
            expected_prev = Some(event.event_hash.clone());
            expected_seq = expected_seq.saturating_add(1);
        }
        *self.head.borrow_mut() = Some(events.last().cloned());
        Ok(())
    }

    pub fn head_seq(&self) -> Result<u64> {
        Ok(self.head()?.map(|event| event.seq).unwrap_or(0))
    }

    pub(crate) fn write_checkpoint(&self, event: &EventEnvelope) -> Result<PathBuf> {
        let path = self.checkpoint_path(event.seq)?;
        if let Some(parent) = path.parent() {
            ensure_log_directory(parent)?;
        }
        let body = serde_json::to_string_pretty(event).context("Could not serialize checkpoint")?;
        crate::fs_atomic::write_atomic(&path, &body)
            .with_context(|| format!("Could not install checkpoint {}", path.display()))?;
        Ok(path)
    }

    pub(crate) fn roll_segment(&self) -> Result<PathBuf> {
        let next = self.active_segment_index()?.saturating_add(1);
        let path = self.segment_path(next);
        let file = create_segment_file(&path)
            .with_context(|| format!("Could not create {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("Could not fsync {}", path.display()))?;
        sync_directory(&self.root)?;
        Ok(path)
    }

    fn head(&self) -> Result<Option<EventEnvelope>> {
        if let Some(cached) = self.head.borrow().clone() {
            return Ok(cached);
        }
        let head = self.read_all()?.last().cloned();
        *self.head.borrow_mut() = Some(head.clone());
        Ok(head)
    }

    fn checkpoint_path(&self, seq: u64) -> Result<PathBuf> {
        Ok(self
            .root
            .join("checkpoints")
            .join(format!("checkpoint-{seq:012}.json")))
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<()> {
        let mut line = serde_json::to_string(envelope).context("Could not serialize event")?;
        line.push('\n');
        anyhow::ensure!(
            line.len() <= MAX_EVENT_LOG_LINE_BYTES,
            "Event log entry exceeds the {MAX_EVENT_LOG_LINE_BYTES}-byte line limit"
        );
        let path = self.segment_path_for_append(line.len() as u64)?;
        let (mut file, created) = open_segment_for_append(&path)?;
        heal_torn_tail(&mut file, &path)?;
        file.write_all(line.as_bytes())
            .context("Could not append event")?;
        file.sync_all().context("Could not fsync event log")?;
        if created {
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    fn segment_path_for_append(&self, line_bytes: u64) -> Result<PathBuf> {
        let segments = self.segment_files()?;
        let total_bytes = segments.iter().try_fold(0u64, |total, (_, path)| {
            fs::symlink_metadata(path).map(|metadata| total.saturating_add(metadata.len()))
        })?;
        anyhow::ensure!(
            total_bytes.saturating_add(line_bytes) <= MAX_EVENT_LOG_TOTAL_BYTES,
            "Event log append would exceed the {MAX_EVENT_LOG_TOTAL_BYTES}-byte aggregate limit"
        );
        let active = self.segment_path(segments.last().map(|(index, _)| *index).unwrap_or(0));
        let current_bytes = match fs::symlink_metadata(&active) {
            Ok(metadata) => {
                validate_segment_metadata(&active, &metadata)?;
                metadata.len()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error).context("Could not inspect active event segment"),
        };
        if current_bytes.saturating_add(line_bytes) > MAX_EVENT_LOG_SEGMENT_BYTES {
            anyhow::ensure!(
                segments.len() < MAX_EVENT_LOG_SEGMENTS,
                "Event log cannot roll beyond the {MAX_EVENT_LOG_SEGMENTS}-segment limit"
            );
            return self.roll_segment();
        }
        Ok(active)
    }

    fn active_segment_index(&self) -> Result<u64> {
        Ok(self
            .segment_files()?
            .last()
            .map(|(index, _)| *index)
            .unwrap_or(0))
    }

    fn segment_files(&self) -> Result<Vec<(u64, PathBuf)>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        let mut total_bytes = 0u64;
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("Could not read {}", self.root.display()))?
        {
            let Some((index, path, bytes)) = validated_segment_entry(entry?)? else {
                continue;
            };
            total_bytes = total_bytes.saturating_add(bytes);
            anyhow::ensure!(
                total_bytes <= MAX_EVENT_LOG_TOTAL_BYTES,
                "Event log exceeds the {MAX_EVENT_LOG_TOTAL_BYTES}-byte aggregate limit"
            );
            files.push((index, path));
            anyhow::ensure!(
                files.len() <= MAX_EVENT_LOG_SEGMENTS,
                "Event log exceeds the {MAX_EVENT_LOG_SEGMENTS}-segment limit"
            );
        }
        files.sort_by_key(|(index, _)| *index);
        Ok(files)
    }

    fn segment_path(&self, index: u64) -> PathBuf {
        self.root.join(format!("events-{index:06}.jsonl"))
    }
}

fn validated_segment_entry(entry: fs::DirEntry) -> Result<Option<(u64, PathBuf, u64)>> {
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
        return Ok(None);
    };
    let Some(index) = segment_index(name) else {
        return Ok(None);
    };
    let path = entry.path();
    let file_type = entry
        .file_type()
        .with_context(|| format!("Could not inspect {}", path.display()))?;
    if file_type.is_symlink() || !file_type.is_file() {
        anyhow::bail!(
            "Event log segment must be a regular non-symlink file: {}",
            path.display()
        );
    }
    let metadata = fs::symlink_metadata(&path)?;
    validate_segment_metadata(&path, &metadata)?;
    Ok(Some((index, path, metadata.len())))
}

fn verify_event_in_chain(
    event: &EventEnvelope,
    expected_seq: u64,
    expected_prev: Option<&Blake3Hash>,
) -> Result<()> {
    if event.seq != expected_seq {
        anyhow::bail!(
            "event sequence is not contiguous: expected {expected_seq}, found {}",
            event.seq
        );
    }
    if event.prev_event_hash.as_ref() != expected_prev {
        anyhow::bail!("event {} has an invalid previous hash", event.seq);
    }
    let expected_hash = event_hash_for_envelope(event)?;
    if event.event_hash != expected_hash {
        anyhow::bail!("event {} hash mismatch", event.seq);
    }
    Ok(())
}

fn event_hash_for_envelope(event: &EventEnvelope) -> Result<Blake3Hash> {
    event_hash(
        event.seq,
        event.prev_event_hash.as_ref(),
        event.event_kind,
        &event.actor,
        event.run_id.as_deref(),
        event.target_snapshot.as_ref(),
        &event.created_at,
        &event.payload,
    )
}

/// Unix directory durability is mandatory. Other platforms retain the weaker
/// namespace guarantee of fs_atomic::sync_parent_dir.
fn sync_directory(path: &Path) -> Result<()> {
    crate::fs_atomic::sync_parent_dir(&path.join(".namespace-sync"))
        .with_context(|| format!("Could not sync event-log directory {}", path.display()))
}

fn ensure_log_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Event log directory must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("Event log path is not a directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).with_context(|| format!("Could not create {}", path.display()))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn read_segment_events(
    path: &Path,
    event_limit: usize,
    allow_torn_tail: bool,
) -> Result<Vec<EventEnvelope>> {
    let mut file = open_segment_for_read(path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_EVENT_LOG_SEGMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("Could not read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_EVENT_LOG_SEGMENT_BYTES,
        "Event log segment exceeds the {MAX_EVENT_LOG_SEGMENT_BYTES}-byte limit"
    );
    let (complete, torn) = split_torn_tail(&bytes);
    validate_torn_tail(path, complete, torn, allow_torn_tail)?;
    let body =
        std::str::from_utf8(complete).context("Could not read event log segment as UTF-8")?;
    parse_segment_body(path, body, event_limit)
}

fn validate_torn_tail(
    path: &Path,
    complete: &[u8],
    torn: &[u8],
    allow_torn_tail: bool,
) -> Result<()> {
    if torn.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        torn.len() <= MAX_EVENT_LOG_LINE_BYTES,
        "Event log line {} exceeds the {MAX_EVENT_LOG_LINE_BYTES}-byte limit in {}",
        complete.iter().filter(|byte| **byte == b'\n').count() + 1,
        path.display()
    );
    anyhow::ensure!(
        allow_torn_tail,
        "Event log segment {} has a torn, newline-less tail outside the active segment",
        path.display()
    );
    crate::runtime_diagnostics::record_runtime_diagnostic(
        "event-log",
        format!(
            "dropping {} torn tail byte(s) from {} (process died mid-append); the next append will truncate them",
            torn.len(),
            path.display()
        ),
    );
    Ok(())
}

/// Split segment bytes into the complete-line region (up to and including
/// the final newline) and any torn tail a killed writer left behind. Every
/// well-formed append ends with `\n`, so a newline-less tail is exactly one
/// interrupted `write`.
fn split_torn_tail(bytes: &[u8]) -> (&[u8], &[u8]) {
    match bytes.iter().rposition(|byte| *byte == b'\n') {
        Some(position) => bytes.split_at(position + 1),
        None => (&[], bytes),
    }
}

fn parse_segment_body(path: &Path, body: &str, event_limit: usize) -> Result<Vec<EventEnvelope>> {
    let mut events = Vec::new();
    for (index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        anyhow::ensure!(
            line.len() <= MAX_EVENT_LOG_LINE_BYTES,
            "Event log line {} exceeds the {MAX_EVENT_LOG_LINE_BYTES}-byte limit in {}",
            index + 1,
            path.display()
        );
        anyhow::ensure!(
            events.len() < event_limit,
            "Event log exceeds the event aggregate limit"
        );
        events.push(parse_event_line(path, index + 1, line.to_string())?);
    }
    Ok(events)
}

/// Truncate a torn, newline-less tail left by a writer killed mid-append.
/// Runs on the single-writer append path (readers only tolerate the tail),
/// so the segment self-heals on the next durable event.
fn heal_torn_tail(file: &mut fs::File, path: &Path) -> Result<()> {
    crate::jsonl_tail::heal_torn_jsonl_tail(
        file,
        path,
        MAX_EVENT_LOG_LINE_BYTES,
        "Event log segment",
    )
}

fn open_segment_for_append(path: &Path) -> Result<(fs::File, bool)> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_segment_metadata(path, &metadata)?;
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", path.display()))
        }
    };
    let file = open_append_no_follow(path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    validate_segment_metadata(path, &file.metadata()?)?;
    Ok((file, created))
}

fn open_segment_for_read(path: &Path) -> Result<fs::File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Could not inspect {}", path.display()))?;
    validate_segment_metadata(path, &metadata)?;
    let file = open_read_no_follow(path)?;
    validate_segment_metadata(path, &file.metadata()?)?;
    Ok(file)
}

fn validate_segment_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "Event log segment must be a regular non-symlink file: {}",
            path.display()
        );
    }
    anyhow::ensure!(
        metadata.len() <= MAX_EVENT_LOG_SEGMENT_BYTES,
        "Event log segment exceeds the {MAX_EVENT_LOG_SEGMENT_BYTES}-byte limit: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn open_append_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // `read` lets the torn-tail healer inspect the segment through the same
    // descriptor; O_APPEND still forces every write to the end.
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_append_no_follow(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
}

#[cfg(unix)]
fn open_read_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_read_no_follow(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn create_segment_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_segment_file(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new().create_new(true).write(true).open(path)
}

fn segment_index(name: &str) -> Option<u64> {
    let suffix = name.strip_prefix("events-")?.strip_suffix(".jsonl")?;
    if suffix.len() != 6 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

fn now_isoish() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}

fn parse_event_line(path: &Path, line_number: usize, line: String) -> Result<EventEnvelope> {
    serde_json::from_str(&line)
        .with_context(|| format!("Invalid event log line {}:{line_number}", path.display()))
}

fn event_hash(
    seq: u64,
    prev_event_hash: Option<&Blake3Hash>,
    event_kind: EventKind,
    actor: &str,
    run_id: Option<&str>,
    target_snapshot: Option<&Blake3Hash>,
    created_at: &str,
    payload: &Value,
) -> Result<Blake3Hash> {
    let seq = seq.to_string();
    let previous = prev_event_hash.map(Blake3Hash::as_str).unwrap_or("none");
    let run_id = run_id.unwrap_or("none");
    let target_snapshot = target_snapshot.map(Blake3Hash::as_str).unwrap_or("none");
    let payload = serde_json::to_vec(payload).context("Could not serialize event payload")?;
    Ok(hash_parts(
        "event",
        &[
            seq.as_bytes(),
            previous.as_bytes(),
            event_kind.as_str().as_bytes(),
            actor.trim().as_bytes(),
            run_id.as_bytes(),
            target_snapshot.as_bytes(),
            created_at.as_bytes(),
            &payload,
        ],
    ))
}

#[cfg(test)]
mod tests;
