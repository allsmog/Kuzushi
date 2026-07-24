use super::{
    RunAttemptId, RunCallId, RunEventId, RunId, RunItemId, RunItemV1, RunTaskId,
    MAX_SERIALIZED_RUN_ITEM_BYTES,
};
use crate::WorkflowPhase;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RUN_ITEM_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunItemSource {
    Dispatch,
    Runtime,
    Workflow,
    Operator,
    Persistence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunItemEnvelopeV1 {
    pub schema_version: u16,
    pub seq: u64,
    pub event_id: RunEventId,
    pub item_id: RunItemId,
    pub run_id: RunId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<RunTaskId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<RunCallId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_item_id: Option<RunItemId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<RunAttemptId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<WorkflowPhase>,
    pub source: RunItemSource,
    pub occurred_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
    pub event_hash: String,
    pub item: RunItemV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunItemRecord {
    pub item_id: RunItemId,
    pub task_id: Option<RunTaskId>,
    pub call_id: Option<RunCallId>,
    pub parent_item_id: Option<RunItemId>,
    pub attempt_id: Option<RunAttemptId>,
    pub phase: Option<WorkflowPhase>,
    pub source: RunItemSource,
    pub item: RunItemV1,
}

impl RunItemRecord {
    pub fn new(item_id: RunItemId, source: RunItemSource, item: RunItemV1) -> Self {
        Self {
            item_id,
            task_id: None,
            call_id: None,
            parent_item_id: None,
            attempt_id: None,
            phase: None,
            source,
            item,
        }
    }

    pub fn with_task(mut self, task_id: RunTaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    pub fn with_call(mut self, call_id: RunCallId) -> Self {
        self.call_id = Some(call_id);
        self
    }

    pub fn with_parent(mut self, parent_item_id: RunItemId) -> Self {
        self.parent_item_id = Some(parent_item_id);
        self
    }

    pub fn with_attempt(mut self, attempt_id: RunAttemptId) -> Self {
        self.attempt_id = Some(attempt_id);
        self
    }

    pub fn with_phase(mut self, phase: WorkflowPhase) -> Self {
        self.phase = Some(phase);
        self
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HashPayload<'a> {
    schema_version: u16,
    seq: u64,
    event_id: RunEventId,
    item_id: RunItemId,
    run_id: &'a RunId,
    task_id: Option<RunTaskId>,
    call_id: Option<RunCallId>,
    parent_item_id: Option<RunItemId>,
    attempt_id: Option<RunAttemptId>,
    phase: Option<WorkflowPhase>,
    source: RunItemSource,
    occurred_at_ms: u64,
    prev_event_hash: &'a Option<String>,
    item: &'a RunItemV1,
}

impl RunItemEnvelopeV1 {
    pub fn from_record(
        seq: u64,
        run_id: RunId,
        record: RunItemRecord,
        prev_event_hash: Option<String>,
    ) -> Result<Self> {
        let mut envelope = Self::new(
            seq,
            run_id,
            record.item_id,
            record.source,
            record.item,
            prev_event_hash,
        )?;
        envelope.task_id = record.task_id;
        envelope.call_id = record.call_id;
        envelope.parent_item_id = record.parent_item_id;
        envelope.attempt_id = record.attempt_id;
        envelope.phase = record.phase;
        envelope.rehash()
    }

    pub fn new(
        seq: u64,
        run_id: RunId,
        item_id: RunItemId,
        source: RunItemSource,
        item: RunItemV1,
        prev_event_hash: Option<String>,
    ) -> Result<Self> {
        let mut envelope = Self::without_hash(seq, run_id, item_id, source, item, prev_event_hash);
        envelope.event_hash = envelope.calculate_hash()?;
        envelope.validate_size()?;
        Ok(envelope)
    }

    pub fn with_task(mut self, task_id: RunTaskId) -> Result<Self> {
        self.task_id = Some(task_id);
        self.rehash()
    }

    pub fn with_call(mut self, call_id: RunCallId) -> Result<Self> {
        self.call_id = Some(call_id);
        self.rehash()
    }

    pub fn with_parent(mut self, parent_item_id: RunItemId) -> Result<Self> {
        self.parent_item_id = Some(parent_item_id);
        self.rehash()
    }

    pub fn with_attempt(mut self, attempt_id: RunAttemptId) -> Result<Self> {
        self.attempt_id = Some(attempt_id);
        self.rehash()
    }

    pub fn with_phase(mut self, phase: WorkflowPhase) -> Result<Self> {
        self.phase = Some(phase);
        self.rehash()
    }

    pub fn verify_hash(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == RUN_ITEM_SCHEMA_VERSION,
            "unknown schema version"
        );
        anyhow::ensure!(
            self.event_hash == self.calculate_hash()?,
            "run item hash mismatch"
        );
        self.validate_size()
    }

    fn without_hash(
        seq: u64,
        run_id: RunId,
        item_id: RunItemId,
        source: RunItemSource,
        item: RunItemV1,
        prev_event_hash: Option<String>,
    ) -> Self {
        Self {
            schema_version: RUN_ITEM_SCHEMA_VERSION,
            seq,
            event_id: RunEventId::new(),
            item_id,
            run_id,
            task_id: None,
            call_id: None,
            parent_item_id: None,
            attempt_id: None,
            phase: None,
            source,
            occurred_at_ms: now_ms(),
            prev_event_hash,
            event_hash: String::new(),
            item,
        }
    }

    fn rehash(mut self) -> Result<Self> {
        self.event_hash = self.calculate_hash()?;
        self.validate_size()?;
        Ok(self)
    }

    fn calculate_hash(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.hash_payload()).context("serialize run item hash")?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    fn hash_payload(&self) -> HashPayload<'_> {
        HashPayload {
            schema_version: self.schema_version,
            seq: self.seq,
            event_id: self.event_id,
            item_id: self.item_id,
            run_id: &self.run_id,
            task_id: self.task_id,
            call_id: self.call_id,
            parent_item_id: self.parent_item_id,
            attempt_id: self.attempt_id,
            phase: self.phase,
            source: self.source,
            occurred_at_ms: self.occurred_at_ms,
            prev_event_hash: &self.prev_event_hash,
            item: &self.item,
        }
    }

    fn validate_size(&self) -> Result<()> {
        let bytes = serde_json::to_vec(self).context("serialize bounded run item")?;
        anyhow::ensure!(
            bytes.len() <= MAX_SERIALIZED_RUN_ITEM_BYTES,
            "run item exceeds 64 KiB"
        );
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
