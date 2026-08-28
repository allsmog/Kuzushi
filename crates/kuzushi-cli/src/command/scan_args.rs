use super::{FailOnArg, ScanModeArg};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub(crate) struct ScanArgs {
    #[arg(help = crate::support::TARGET_HELP)]
    pub(crate) target: Option<PathBuf>,
    /// Scan mode: `standard` or `whitebox-static`.
    #[arg(long, value_enum)]
    pub(crate) mode: Option<ScanModeArg>,
    /// Restrict the scan to these DAG tasks (comma- or repeat-separated).
    #[arg(long, value_delimiter = ',')]
    pub(crate) tasks: Vec<String>,
    /// Run model-backed triage on recorded findings after the scan.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub(crate) triage: Option<bool>,
    /// Emit the scan result as a single machine-readable JSON object.
    #[arg(long)]
    pub(crate) json: bool,
    /// Emit one line per pipeline event in a deterministic, grep-friendly format.
    #[arg(long, conflicts_with = "json")]
    pub(crate) ci: bool,
    /// Per-operation USD budget caps, e.g. `triage=50,deep-audit=200,full-mode-multi=300`.
    /// Caps are persisted to the spend ledger and enforced by spend-aware
    /// model-backed operations before they reserve estimated LLM spend.
    /// Scanner-only work and tools that do not report spend are unaffected.
    #[arg(long)]
    pub(crate) budget: Option<String>,
    /// Scan only the named shard from the shard manifest — a reusable,
    /// workspace-relative scope declared as `[shards.<name>] paths = [...]`
    /// in `<target>/.kuzushi/shards.toml` (or `--shard-manifest <file>`).
    /// Compiles into the canonical `sast:scan` `paths` option and records
    /// the shard name in run provenance.
    #[arg(long)]
    pub(crate) shard: Option<String>,
    /// Shard manifest file to resolve `--shard` against. Defaults to
    /// `<target>/.kuzushi/shards.toml`.
    #[arg(long, requires = "shard")]
    pub(crate) shard_manifest: Option<PathBuf>,
    /// Restrict the scan to these workspace-relative path roots (comma- or
    /// repeat-separated) without a manifest. Mutually exclusive with `--shard`.
    #[arg(long, value_delimiter = ',', conflicts_with = "shard")]
    pub(crate) paths: Vec<String>,
    /// Diff-scope the scan to files changed since `<ref>`. Engines that
    /// support it (full-mode-multi today) narrow their walk; others are
    /// unaffected. Pass `--include-worktree` to include uncommitted edits.
    #[arg(long)]
    pub(crate) since: Option<String>,
    /// When `--since` is set, also include uncommitted (working-tree) changes.
    #[arg(long, requires = "since")]
    pub(crate) include_worktree: bool,
    /// Exit with code 3 when any finding at or above this severity is
    /// recorded by the scan. Lets CI block a PR on findings; without it
    /// the scan exits 0 regardless of what it found.
    #[arg(long, value_enum)]
    pub(crate) fail_on: Option<FailOnArg>,
    /// Write a SARIF 2.1.0 export of this workspace's findings to the
    /// given path after the scan (for GitHub Code Scanning upload etc.).
    #[arg(long)]
    pub(crate) sarif: Option<PathBuf>,
    /// Repeat the exact prepared scan as N logical trials. Aliases
    /// `--attempts` and `--samples` are accepted for compatibility;
    /// dispatcher retries remain separate from trials.
    #[arg(long, aliases = ["attempts", "samples"], default_value_t = 1)]
    pub(crate) trials: usize,
    /// Maximum detached scan-trial child processes to run concurrently.
    /// Resource claims may clamp this to one; only applies with --trials.
    #[arg(long, default_value_t = 1)]
    pub(crate) workers: usize,
}
