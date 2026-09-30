use clap::Parser;
use std::path::PathBuf;

pub(crate) const PM_LINES_PRIMARY: i64 = 10;
pub(crate) const PM_LINES_FUNCTION_FALLBACK: i64 = 50;

pub(crate) fn parse_non_negative_cost_usd(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| "cost must be a finite, non-negative USD amount".to_string())?;
    if !parsed.is_finite() || parsed.is_sign_negative() {
        return Err("cost must be a finite, non-negative USD amount".to_string());
    }
    Ok(parsed)
}

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

    /// Measured USD cost of the scan that produced the findings.
    /// Omit when unavailable; the report will encode `null`, not a synthetic zero.
    #[arg(long, value_parser = parse_non_negative_cost_usd)]
    pub(crate) cost_usd: Option<f64>,

    /// Wall-clock seconds spent on the scan that produced the findings.
    #[arg(long, default_value_t = 0)]
    pub(crate) wall_seconds: u64,

    /// Pretty-print the output JSON.
    #[arg(long, default_value_t = true)]
    pub(crate) pretty: bool,

    /// Return a nonzero status when primary recall is below the oracle threshold.
    #[arg(long)]
    pub(crate) enforce_threshold: bool,
}
