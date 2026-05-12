use crate::findings::Finding;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default chunk budget in approximate tokens. Sized so a chunk fits in
/// a single 200k-context call with room for the system prompt and output.
pub const DEFAULT_MAX_TOKENS_PER_CHUNK: usize = 12_000;

/// Approximate bytes-per-token used for chunk packing without invoking a
/// runtime tokenizer.
pub const BYTES_PER_TOKEN: f64 = 3.6;

/// Hard cap on per-file size before we silently skip the file. The
/// intent is "if this file's token estimate exceeds MAX_FILE_TOKENS,
/// it's too big for a single chunk and gets dropped". Computing the
/// byte cap as `MAX_FILE_TOKENS * BYTES_PER_TOKEN as usize` was a
/// silent truncation bug: `BYTES_PER_TOKEN` is `3.6` but `as usize`
/// rounds toward zero, so the cap collapsed to `80_000 * 3 = 240_000`
/// bytes. A 250 KB `fs/smb/server/smb2pdu.c` (≈68k est-tokens, well
/// under MAX_FILE_TOKENS) was silently skipped from every kernel
/// scan. Use the float multiplication path so the cap matches its
/// documented intent.
pub const MAX_FILE_BYTES: usize = (MAX_FILE_TOKENS as f64 * BYTES_PER_TOKEN) as usize;

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
    /// Optional chunk-id filter: when set, only matching planned chunk IDs are executed.
    /// Used to retry only failed chunks from a previous broad run.
    #[serde(default)]
    pub failed_chunk_ids: Option<Vec<u32>>,
    /// If `true`, run deep-audit on every HIGH+CRITICAL finding the
    /// chunk pass emits, BEFORE persisting. Each finding's triage
    /// verdict is then attached and the deep-audit cost is summed into
    /// the report. Default false to keep the cheap-cast-wide-net mode
    /// unchanged; set true for "scan + triage in one shot."
    #[serde(default)]
    pub auto_triage: bool,
    /// When auto-triaging, the per-finding deep-audit step budget.
    /// Default 12, same as `deep-audit:run`'s recommended floor.
    #[serde(default)]
    pub auto_triage_max_steps: Option<u32>,
    /// When auto-triaging, the per-finding deep-audit deposit. Default
    /// 1.0; deep-audit refunds unused budget.
    #[serde(default)]
    pub auto_triage_deposit_usd: Option<f64>,
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
            failed_chunk_ids: None,
            auto_triage: false,
            auto_triage_max_steps: None,
            auto_triage_deposit_usd: None,
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
    #[serde(default)]
    pub failed_chunk_errors: Vec<FailedChunkError>,
    pub cost_usd: f64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedChunkError {
    pub chunk_id: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub chunks: usize,
    pub files: usize,
    pub total_tokens: usize,
    pub usd_low: f64,
    pub usd_high: f64,
}

#[cfg(test)]
mod tests {
    use super::{BYTES_PER_TOKEN, MAX_FILE_BYTES, MAX_FILE_TOKENS};

    #[test]
    fn max_file_bytes_matches_documented_intent() {
        // Regression for a silent `as usize` truncation that dropped the
        // 0.6 fractional part of BYTES_PER_TOKEN, collapsing the per-file
        // size cap from 288_000 → 240_000 bytes and excluding files like
        // fs/smb/server/smb2pdu.c (~250 KB) from every full-mode scan.
        assert_eq!(MAX_FILE_BYTES, 288_000);
        assert_eq!(
            MAX_FILE_BYTES,
            (MAX_FILE_TOKENS as f64 * BYTES_PER_TOKEN) as usize
        );
    }
}
