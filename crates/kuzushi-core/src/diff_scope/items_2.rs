use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DiffFileStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    TypeChanged,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangedLineRange {
    pub start_line: u32,
    pub end_line: u32,
    pub kind: DiffRangeKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DiffRangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffContext {
    pub kind: DiffContextKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub detail: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiffContextKind {
    ChangedFile,
    Route,
    Caller,
    Callee,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffFindingTag {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub status: DiffFindingStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DiffFindingStatus {
    New,
    Existing,
    Fixed,
    ChangedContext,
}

impl DiffFindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Existing => "existing",
            Self::Fixed => "fixed",
            Self::ChangedContext => "changed-context",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffScopeSummary {
    pub changed_files: usize,
    pub changed_ranges: usize,
    pub deleted_ranges: usize,
    pub context_items: usize,
    pub new_findings: usize,
    pub existing_findings: usize,
    pub fixed_findings: usize,
    pub changed_context_findings: usize,
}
