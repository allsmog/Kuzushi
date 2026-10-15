//! Private editor checkpoints carry no model, job, approval or accepted context.
use crate::ThreatModelRef;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
mod store;
pub use store::ContextDraftStore;

pub(super) const MAX_DRAFT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ORIGINS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftText {
    pub text: String,
    pub cursor: usize,
}

impl DraftText {
    fn validate(&self, maximum: usize) -> Result<()> {
        anyhow::ensure!(
            self.text.len() <= maximum,
            "Draft text exceeds its byte limit"
        );
        anyhow::ensure!(!self.text.contains('\0'), "Draft text contains a null byte");
        anyhow::ensure!(
            self.cursor <= self.text.chars().count(),
            "Draft cursor is outside its text"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextDraftField {
    pub pointer: String,
    /// Unchanged text is read from the authenticated base context.
    pub text: Option<String>,
    pub cursor: usize,
}

impl ContextDraftField {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.pointer.starts_with('/') && self.pointer.len() <= 4096,
            "Invalid draft field pointer"
        );
        anyhow::ensure!(
            self.cursor <= MAX_DRAFT_BYTES,
            "Draft field cursor exceeds its limit"
        );
        if let Some(text) = &self.text {
            DraftText {
                text: text.clone(),
                cursor: self.cursor,
            }
            .validate(crate::capabilities::threat_model::MAX_CONTEXT_EDIT_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDraftMode {
    Fields,
    Writing,
    Review,
    Saving,
    Discard,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextDraftSnapshot {
    pub name: DraftText,
    pub fields: Vec<ContextDraftField>,
    pub selected_pointer: Option<String>,
    pub scroll: usize,
    pub mode: ContextDraftMode,
    /// Exact records adopted during recovery; resolving never erases another edit.
    pub origin_hashes: Vec<String>,
}

impl ContextDraftSnapshot {
    fn validate(&self) -> Result<()> {
        self.name.validate(2048)?;
        anyhow::ensure!(
            self.selected_pointer
                .as_ref()
                .is_none_or(|pointer| pointer.starts_with('/') && pointer.len() <= 4096),
            "Invalid selected draft field"
        );
        anyhow::ensure!(
            self.fields.len() <= crate::capabilities::threat_model::MAX_CONTEXT_EDITS + 1,
            "Too many checkpointed context fields"
        );
        anyhow::ensure!(
            self.scroll <= MAX_DRAFT_BYTES,
            "Draft scroll exceeds its limit"
        );
        let mut pointers = BTreeSet::new();
        for field in &self.fields {
            field.validate()?;
            anyhow::ensure!(
                pointers.insert(&field.pointer),
                "Duplicate draft field pointer"
            );
        }
        validate_origins(&self.origin_hashes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextDraftRecord {
    pub version: u8,
    pub target: PathBuf,
    pub source: ThreatModelRef,
    pub session_id: String,
    #[serde(default)]
    pub saved_at_seconds: u64,
    pub snapshot: Option<ContextDraftSnapshot>,
    pub resolved_hashes: Vec<String>,
}

impl ContextDraftRecord {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.version == 1, "Unsupported context draft version");
        anyhow::ensure!(
            self.target.is_absolute(),
            "Context draft target is not absolute"
        );
        super::store::validate_session_id(&self.session_id)?;
        validate_origins(&self.resolved_hashes)?;
        if let Some(snapshot) = &self.snapshot {
            snapshot.validate()?;
        }
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= MAX_DRAFT_BYTES,
            "Context draft exceeds its recovery limit"
        );
        Ok(())
    }
}

fn validate_origins(hashes: &[String]) -> Result<()> {
    anyhow::ensure!(
        hashes.len() <= MAX_ORIGINS,
        "Context draft recovery chain exceeds its limit"
    );
    for hash in hashes {
        anyhow::ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid context draft record hash"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredContextDraft {
    pub record: ContextDraftRecord,
    pub record_hash: String,
}
