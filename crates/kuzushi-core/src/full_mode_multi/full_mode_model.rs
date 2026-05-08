use super::*;

pub const DEFAULT_MAX_TOKENS_PER_CHUNK: usize = 120_000;

pub const BYTES_PER_TOKEN: f64 = 3.6;

pub const MAX_FILE_BYTES: usize = MAX_FILE_TOKENS * BYTES_PER_TOKEN as usize;

pub(crate) const MAX_FILE_TOKENS: usize = 80_000;

pub(crate) const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".kuzushi",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

pub const DEFAULT_DEPOSIT_USD_PER_CHUNK: f64 = 2.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullModeConfig {
    pub workspace_root: PathBuf,
    pub max_tokens_per_chunk: usize,
    pub deposit_usd_per_chunk: f64,
    /// File extensions to include. Empty = `["c","cc","cpp","cxx","h","hh","hpp","hxx"]`.
    #[serde(default)]
    pub include_extensions: Vec<String>,
    /// Language for the prompt selector — `"c"`, `"unknown"`. `"java"`
    /// will be supported in a follow-up.
    pub language: FullModeLanguage,
    /// If `true`, the dispatcher returns the chunk plan + cost estimate
    /// without invoking any model. Always run this on a fresh slice.
    pub dry_run: bool,
    /// Optional diff-scope filter: when set, only files whose relative
    /// path appears in `scope_files` are included in the plan. Used by
    /// the `--since <ref>` flag to scan only what changed.
    #[serde(default)]
    pub scope_files: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FullModeLanguage {
    C,
    Unknown,
}

impl Default for FullModeConfig {
    fn default() -> Self {
        Self {
            workspace_root: PathBuf::from("."),
            max_tokens_per_chunk: DEFAULT_MAX_TOKENS_PER_CHUNK,
            deposit_usd_per_chunk: DEFAULT_DEPOSIT_USD_PER_CHUNK,
            include_extensions: Vec::new(),
            language: FullModeLanguage::C,
            dry_run: false,
            scope_files: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBucket {
    pub path: String,
    pub bytes: usize,
    pub est_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPlan {
    pub id: u32,
    pub files: Vec<FileBucket>,
    pub est_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullModePlan {
    pub chunks: Vec<ChunkPlan>,
    pub total_files: usize,
    pub total_bytes: usize,
    pub total_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullModeReport {
    pub findings: Vec<Finding>,
    pub plan: FullModePlan,
    pub chunks_dispatched: u32,
    pub chunks_failed: u32,
    pub cost_usd: f64,
    pub dry_run: bool,
}
