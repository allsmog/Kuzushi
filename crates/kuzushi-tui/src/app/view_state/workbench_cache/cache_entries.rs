use crate::app::RunSummaryEntriesState;
use kuzushi_core::workspace::ProjectModelDocument;
use kuzushi_core::{
    LatestRunPointerState, NestedProjectScopeTree, PromptMutation, RunSummary, RunSummaryEntry,
    RunSummaryEntryState, RunTargetGitMetadata, StrategyProposal,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(super) fn run_summary_index_from_entries(
    entries: &[RunSummaryEntry],
) -> BTreeMap<String, RunSummary> {
    entries
        .iter()
        .filter_map(|entry| match &entry.state {
            RunSummaryEntryState::Ready(summary) => Some((summary.run_id.clone(), summary.clone())),
            RunSummaryEntryState::Issue(_) => None,
        })
        .collect()
}

pub(super) fn project_scope_tree_for_target(target: &Path) -> ProjectScopeTreeState {
    match kuzushi_core::load_nested_project_scopes(target) {
        Ok(Some(tree)) => ProjectScopeTreeState::Persisted(tree),
        Ok(None) => ProjectScopeTreeState::RootOnly,
        Err(error) => ProjectScopeTreeState::Unreadable(error.to_string()),
    }
}

#[cfg(test)]
pub(super) fn read_json_file(path: &Path) -> JsonFileState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return JsonFileState::NonFile,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return JsonFileState::Missing;
        }
        Err(_) => return JsonFileState::Unreadable,
    };
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return JsonFileState::Unreadable,
    };
    serde_json::from_str::<serde_json::Value>(&raw)
        .map(JsonFileState::Present)
        .unwrap_or(JsonFileState::Malformed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectScopeTreeState {
    Persisted(NestedProjectScopeTree),
    RootOnly,
    Unreadable(String),
}

#[derive(Debug, Clone)]
pub(crate) enum StrategyQueueState {
    Ready(Vec<StrategyProposal>),
    Unreadable(String),
}

#[derive(Debug, Clone)]
pub(crate) enum PromptMutationsState {
    Ready(Vec<PromptMutation>),
    Unreadable,
}

#[derive(Debug, Clone)]
pub(crate) enum JsonFileState {
    Present(serde_json::Value),
    Missing,
    NonFile,
    Malformed,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathState {
    File { len: u64 },
    Directory,
    Other,
    Missing,
    Unreadable,
}

#[derive(Debug, Clone)]
pub(crate) enum DirectoryListingState {
    Ready(Vec<PathBuf>),
    Missing,
    NonDirectory,
    Unreadable,
}

#[derive(Debug, Clone)]
pub(crate) enum RunTraceCacheState {
    Ready(kuzushi_core::RunTraceRead),
    Invalid,
}

#[derive(Debug)]
pub(super) struct RunProjectionCache {
    pub(super) state: Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>,
    pub(super) bytes: usize,
}

#[derive(Debug)]
pub(super) struct TargetBaseCache {
    pub(super) target: PathBuf,
    pub(super) base: String,
}

#[derive(Debug)]
pub(super) struct TargetProfileCache {
    pub(super) target: PathBuf,
    pub(super) profile: crate::app::TargetProfile,
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct RunSummaryCache {
    pub(super) key: RunSummaryCacheKey,
    pub(super) summaries: BTreeMap<String, RunSummary>,
}

#[derive(Debug)]
pub(super) struct RunSummaryEntriesCache {
    pub(super) target: PathBuf,
    pub(super) state: RunSummaryEntriesState,
}

#[derive(Debug)]
pub(super) struct CompletionValuesCache {
    pub(super) target: PathBuf,
    pub(super) values: Vec<String>,
}

#[derive(Debug)]
pub(super) struct FileCompletionValuesCache {
    pub(super) target: PathBuf,
    pub(super) index: crate::app::FileCompletionIndex,
}

#[derive(Debug)]
pub(super) struct LatestRunPointerCache {
    pub(super) target: PathBuf,
    pub(super) state: LatestRunPointerState,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RunSummaryCacheKey {
    pub(super) target: PathBuf,
    pub(super) scan_ids: Vec<String>,
}

#[derive(Debug)]
pub(super) struct SourceFileCache {
    pub(super) path: PathBuf,
    pub(super) state: Result<String, String>,
}

#[derive(Debug)]
pub(super) struct GitMetadataCache {
    pub(super) target: PathBuf,
    pub(super) metadata: Option<RunTargetGitMetadata>,
}

#[derive(Debug)]
pub(super) struct ScopeTreeCache {
    pub(super) target: PathBuf,
    pub(super) state: ProjectScopeTreeState,
}

#[derive(Debug)]
pub(super) struct ProjectModelDocumentCache {
    pub(super) target: PathBuf,
    pub(super) scope_id: String,
    pub(super) revision: Option<String>,
    pub(super) document: Option<ProjectModelDocument>,
}

#[derive(Debug)]
pub(super) struct StrategyQueueCache {
    pub(super) target: PathBuf,
    pub(super) state: StrategyQueueState,
}

#[derive(Debug)]
pub(super) struct PromptMutationsCache {
    pub(super) target: PathBuf,
    pub(super) state: PromptMutationsState,
}

#[derive(Debug)]
pub(super) struct JsonFileCache {
    pub(super) state: JsonFileState,
}

#[derive(Debug)]
pub(super) struct PathStateCache {
    pub(super) state: PathState,
}

#[derive(Debug)]
pub(super) struct DirectoryListingCache {
    pub(super) state: DirectoryListingState,
}

#[derive(Debug)]
pub(super) struct RunTraceCache {
    pub(super) state: RunTraceCacheState,
    pub(super) bytes: usize,
}

#[derive(Debug)]
pub(super) struct RunArtifactTextCache {
    pub(super) state: kuzushi_core::RunArtifactTextRead,
    pub(super) bytes: usize,
}
