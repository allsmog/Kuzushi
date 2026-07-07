use kuzushi_core::{
    list_run_summaries, NestedProjectScopeTree, PromptMutation, RunSummary, RunTargetGitMetadata,
    StrategyProposal,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const GIT_METADATA_TTL: Duration = Duration::from_secs(2);
const SCOPE_TREE_TTL: Duration = Duration::from_secs(2);

pub(super) fn canonical_target_base(target: &Path) -> String {
    target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

pub(super) fn run_summary_index_for_target(target: &Path) -> BTreeMap<String, RunSummary> {
    list_run_summaries(target)
        .unwrap_or_default()
        .into_iter()
        .map(|summary| (summary.run_id.clone(), summary))
        .collect()
}

pub(super) fn project_scope_tree_for_target(target: &Path) -> ProjectScopeTreeState {
    match kuzushi_core::load_nested_project_scopes(target) {
        Ok(Some(tree)) => ProjectScopeTreeState::Persisted(tree),
        Ok(None) => ProjectScopeTreeState::RootOnly,
        Err(error) => ProjectScopeTreeState::Unreadable(error.to_string()),
    }
}

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

pub(super) fn source_file_stamp(path: &Path) -> std::io::Result<SourceFileStamp> {
    let metadata = std::fs::metadata(path)?;
    Ok(SourceFileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
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

#[derive(Debug)]
pub(super) struct TargetBaseCache {
    pub(super) target: PathBuf,
    pub(super) base: String,
}

#[derive(Debug)]
pub(super) struct RunSummaryCache {
    pub(super) key: RunSummaryCacheKey,
    pub(super) summaries: BTreeMap<String, RunSummary>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RunSummaryCacheKey {
    pub(super) target: PathBuf,
    pub(super) scan_ids: Vec<String>,
}

#[derive(Debug)]
pub(super) struct SourceFileCache {
    pub(super) path: PathBuf,
    pub(super) stamp: SourceFileStamp,
    pub(super) contents: String,
}

#[derive(Debug)]
pub(super) struct GitMetadataCache {
    pub(super) target: PathBuf,
    pub(super) cached_at: Instant,
    pub(super) metadata: Option<RunTargetGitMetadata>,
}

#[derive(Debug)]
pub(super) struct ScopeTreeCache {
    pub(super) target: PathBuf,
    pub(super) cached_at: Instant,
    pub(super) state: ProjectScopeTreeState,
}

#[derive(Debug)]
pub(super) struct StrategyQueueCache {
    pub(super) target: PathBuf,
    pub(super) stamp: Option<SourceFileStamp>,
    pub(super) state: StrategyQueueState,
}

#[derive(Debug)]
pub(super) struct PromptMutationsCache {
    pub(super) target: PathBuf,
    pub(super) stamp: Option<SourceFileStamp>,
    pub(super) state: PromptMutationsState,
}

#[derive(Debug)]
pub(super) struct JsonFileCache {
    pub(super) stamp: Option<SourceFileStamp>,
    pub(super) state: JsonFileState,
}

impl GitMetadataCache {
    pub(super) fn fresh_at(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) <= GIT_METADATA_TTL
    }
}

impl ScopeTreeCache {
    pub(super) fn fresh_at(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) <= SCOPE_TREE_TTL
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SourceFileStamp {
    len: u64,
    modified: Option<SystemTime>,
}
