//! Bounded immutable source input for standard model Review.
use super::*;
use crate::content_store::{ContentStore, ObjectKind};
use crate::findings::ReviewCapturedFile;
use serde::{Deserialize, Serialize};

mod capture;
mod persistence;
mod recorded_sources;
mod request;
mod supporting_files;
pub(crate) use capture::freeze;
pub(crate) use persistence::inspect;
use recorded_sources::RecordedSources;
pub(super) use request::{load_for_execution, model_note};

pub const DEFAULT_REVIEW_SOURCE_BYTES: usize = 32 * 1024;
pub const MAX_REVIEW_SUPPORTING_FILES: usize = 16;
const MAX_REVIEW_SOURCE_BYTES: usize = 256 * 1024;
const REFERENCE_PREFIX: &str = "review-evidence:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSourceEvidence {
    pub schema_version: u32,
    pub target: String,
    pub snapshot_hash: String,
    pub tree_hash: String,
    pub max_bytes: usize,
    pub included_bytes: usize,
    pub observations: Vec<ReviewSourceObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSourceObservation {
    pub generation_id: i64,
    pub path: String,
    pub binding: ReviewSourceBinding,
    pub file: Option<ReviewCapturedFile>,
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supporting_files: Vec<ReviewSupportingFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSupportingFile {
    pub file: ReviewCapturedFile,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSourceBinding {
    MatchingRecordedSnapshot,
    RecordedSourceChanged,
    RecordedSourceUnavailable,
    ByteLimitReached,
}

impl ReviewSourceObservation {
    /// Exact repository-data block added to this generation's Review user prompt.
    pub fn model_input(&self) -> String {
        let primary = match &self.text {
            Some(text) => crate::runbooks::untrusted::render_untrusted_repo_section(&[(self.path.clone(), text.clone())]),
            None => format!("No primary source text was supplied. Frozen source receipt: binding={:?}, file={:?}. Missing text does not establish a fix or refute the finding.",
                self.binding, self.file.as_ref().map(|file| file.state)),
        };
        if self.supporting_files.is_empty() {
            return primary;
        }
        let items = self.supporting_files.iter().map(|source| {
            let text = source.text.clone().unwrap_or_else(|| format!(
                "Source text omitted. Frozen file receipt: {:?}. Missing text does not refute the finding.", source.file.state));
            (source.file.path.clone(), text)
        }).collect::<Vec<_>>();
        format!(
            "{primary}\n\n{}",
            crate::runbooks::untrusted::render_untrusted_repo_section(&items)
        )
    }
}

fn cited_enabled(input: &Value) -> Result<bool> {
    match input.get("sourceEvidence").and_then(Value::as_str) {
        None | Some("none") => Ok(false),
        Some("cited") => Ok(true),
        _ => anyhow::bail!("sourceEvidence must be none or cited"),
    }
}

fn byte_limit(input: &Value) -> Result<usize> {
    let value = input["maxSourceEvidenceBytes"]
        .as_u64()
        .unwrap_or(DEFAULT_REVIEW_SOURCE_BYTES as u64);
    anyhow::ensure!(
        (1..=MAX_REVIEW_SOURCE_BYTES as u64).contains(&value),
        "Source evidence allowance must be 1 to 262144 bytes"
    );
    Ok(value as usize)
}

fn validate_policy(input: &Value) -> Result<bool> {
    let enabled = cited_enabled(input)?;
    let supporting = supporting_files::selected_paths(input)?;
    if !enabled {
        anyhow::ensure!(
            input.get("sourceEvidenceRef").is_none() && supporting.is_empty(),
            "A source-evidence reference or supporting files require sourceEvidence=cited"
        );
        return Ok(false);
    }
    anyhow::ensure!(input["strategy"] == "standard",
        "Cited source evidence is for standard Review; deep strategies use their declared source tools");
    Ok(true)
}
