use clap::Parser;
use std::path::PathBuf;

pub(crate) const PM_LINES_PRIMARY: i64 = 10;
pub(crate) const PM_LINES_FUNCTION_FALLBACK: i64 = 50;

#[derive(Debug, Parser)]
#[command(
    name = "kuzushi-eval",
    about = "Score Kuzushi findings against an oracle"
)]
pub(crate) struct Cli {
    /// Oracle JSON file (e.g. experiments/recall-eval/oracles/linux-cve-2026-31431.json).
    #[arg(long)]
    pub(crate) oracle: PathBuf,

    /// Findings JSON dump from `kuzushi findings --target <slice> --json`.
    #[arg(long)]
    pub(crate) findings: PathBuf,

    /// Slice name (e.g. "linux"). Used in the output for grouping.
    #[arg(long)]
    pub(crate) slice: String,

    /// Slice root directory; used to normalise file paths to repo-relative.
    #[arg(long)]
    pub(crate) target: PathBuf,

    /// Wall-clock seconds spent on the scan that produced the findings.
    #[arg(long, default_value_t = 0)]
    pub(crate) wall_seconds: u64,

    /// Pretty-print the output JSON.
    #[arg(long, default_value_t = true)]
    pub(crate) pretty: bool,
}
