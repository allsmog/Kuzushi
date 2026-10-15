use super::*;
use crate::content_store::{ObjectKind, ObjectRef};
use serde::{Deserialize, Serialize};

pub const MAX_BRIEF_TEXT_BYTES: usize = 8192;
pub(super) const MAX_DOCUMENT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BriefReference {
    pub schema_version: u32,
    pub brief_id: String,
    pub revision: u32,
    pub object: ObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BriefDocument {
    pub schema_version: u32,
    pub brief_id: String,
    pub revision: u32,
    pub target: String,
    pub text: String,
    pub previous: Option<BriefReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BriefRevision {
    pub reference: BriefReference,
    pub document: BriefDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BriefGuidanceV1 {
    pub schema_version: u32,
    pub reference: BriefReference,
    pub text_bytes: usize,
    pub text: String,
}

pub(super) fn validate_id(id: &str) -> Result<()> {
    super::super::validate_scan_batch_id(id)?;
    anyhow::ensure!(id.len() <= 64, "Brief id exceeds 64 bytes");
    Ok(())
}

pub(super) fn validate_text(text: &str) -> Result<()> {
    anyhow::ensure!(
        !text.trim().is_empty(),
        "Enter a goal and priorities before saving the brief"
    );
    anyhow::ensure!(
        text.len() <= MAX_BRIEF_TEXT_BYTES,
        "Brief text exceeds {MAX_BRIEF_TEXT_BYTES} bytes"
    );
    Ok(())
}

impl BriefReference {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_id(&self.brief_id)?;
        anyhow::ensure!(
            self.schema_version == 1 && self.revision > 0,
            "Unsupported brief reference"
        );
        anyhow::ensure!(
            self.object.kind == ObjectKind::Blob
                && self.object.size_bytes <= MAX_DOCUMENT_BYTES as u64,
            "Brief reference exceeds its bounded blob contract"
        );
        Ok(())
    }
}

impl BriefDocument {
    pub(super) fn validate(&self, reference: &BriefReference, target: &str) -> Result<()> {
        reference.validate()?;
        validate_text(&self.text)?;
        anyhow::ensure!(
            self.schema_version == 1 && self.target == target,
            "Brief belongs to a different target or schema"
        );
        anyhow::ensure!(
            self.brief_id == reference.brief_id && self.revision == reference.revision,
            "Brief reference does not identify the document"
        );
        self.validate_lineage()
    }

    fn validate_lineage(&self) -> Result<()> {
        let Some(previous) = &self.previous else {
            anyhow::ensure!(
                self.revision == 1,
                "Brief revision has no previous reference"
            );
            return Ok(());
        };
        previous.validate()?;
        anyhow::ensure!(
            previous.brief_id == self.brief_id
                && previous.revision.checked_add(1) == Some(self.revision),
            "Brief revision lineage is inconsistent"
        );
        Ok(())
    }
}
