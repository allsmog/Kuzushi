use crate::identity::{hash_parts, Blake3Hash};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    ModelCallRecorded,
    PluginInvocationRecorded,
    DiagnosticRecorded,
    ProjectionCheckpointed,
    CompactionCompleted,
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
            Self::ModelCallRecorded => "model-call-recorded",
            Self::PluginInvocationRecorded => "plugin-invocation-recorded",
            Self::DiagnosticRecorded => "diagnostic-recorded",
            Self::ProjectionCheckpointed => "projection-checkpointed",
            Self::CompactionCompleted => "compaction-completed",
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
}

impl EventLog {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        fs::create_dir_all(root).with_context(|| format!("Could not create {}", root.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn append(
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
        Ok(envelope)
    }

    pub fn read_all(&self) -> Result<Vec<EventEnvelope>> {
        let mut events = Vec::new();
        for (_, path) in self.segment_files()? {
            events.extend(read_segment_events(&path)?);
        }
        Ok(events)
    }

    pub fn verify_chain(&self) -> Result<()> {
        let mut expected_prev = None;
        for event in self.read_all()? {
            if event.prev_event_hash != expected_prev {
                anyhow::bail!("event {} has an invalid previous hash", event.seq);
            }
            let expected_hash = event_hash(
                event.seq,
                event.prev_event_hash.as_ref(),
                event.event_kind,
                &event.actor,
                event.run_id.as_deref(),
                event.target_snapshot.as_ref(),
                &event.created_at,
                &event.payload,
            )?;
            if event.event_hash != expected_hash {
                anyhow::bail!("event {} hash mismatch", event.seq);
            }
            expected_prev = Some(event.event_hash);
        }
        Ok(())
    }

    pub fn head_seq(&self) -> Result<u64> {
        Ok(self.head()?.map(|event| event.seq).unwrap_or(0))
    }

    pub fn write_checkpoint(&self, event: &EventEnvelope) -> Result<PathBuf> {
        let path = self.checkpoint_path(event.seq)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(event).context("Could not serialize checkpoint")?;
        fs::write(&tmp, body).with_context(|| format!("Could not write {}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .with_context(|| format!("Could not install checkpoint {}", path.display()))?;
        Ok(path)
    }

    pub fn roll_segment(&self) -> Result<PathBuf> {
        let next = self.active_segment_index()?.saturating_add(1);
        let path = self.segment_path(next);
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("Could not create {}", path.display()))?;
        Ok(path)
    }

    fn head(&self) -> Result<Option<EventEnvelope>> {
        Ok(self.read_all()?.into_iter().last())
    }

    fn checkpoint_path(&self, seq: u64) -> Result<PathBuf> {
        Ok(self
            .root
            .join("checkpoints")
            .join(format!("checkpoint-{seq:012}.json")))
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<()> {
        let path = self.active_segment_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Could not open {}", path.display()))?;
        let line = serde_json::to_string(envelope).context("Could not serialize event")?;
        writeln!(file, "{line}").context("Could not append event")?;
        file.sync_all().context("Could not fsync event log")?;
        Ok(())
    }

    fn active_segment_path(&self) -> Result<PathBuf> {
        Ok(self.segment_path(self.active_segment_index()?))
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
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("Could not read {}", self.root.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(index) = segment_index(name) else {
                continue;
            };
            files.push((index, entry.path()));
        }
        files.sort_by_key(|(index, _)| *index);
        Ok(files)
    }

    fn segment_path(&self, index: u64) -> PathBuf {
        self.root.join(format!("events-{index:06}.jsonl"))
    }
}

fn read_segment_events(path: &Path) -> Result<Vec<EventEnvelope>> {
    let file =
        fs::File::open(path).with_context(|| format!("Could not open {}", path.display()))?;
    let reader = BufReader::new(file);
    reader
        .lines()
        .enumerate()
        .filter_map(|(index, line)| match line {
            Ok(line) if line.trim().is_empty() => None,
            Ok(line) => Some(parse_event_line(path, index + 1, line)),
            Err(error) => Some(Err(error).context("Could not read event log line")),
        })
        .collect()
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
