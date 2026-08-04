use super::FailOnArg;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub(crate) struct InvestigateArgs {
    #[arg(help = crate::support::TARGET_HELP)]
    pub(crate) target: Option<PathBuf>,
    /// Campaign profile: standard, deep, prove, or fix.
    #[arg(
        long,
        default_value = "standard",
        value_parser = ["standard", "deep", "prove", "fix"]
    )]
    pub(crate) profile: String,
    /// Print the fully expanded canonical scan plan without executing it.
    #[arg(long)]
    pub(crate) plan: bool,
    /// Emit the plan or scan result as machine-readable JSON.
    #[arg(long)]
    pub(crate) json: bool,
    /// Emit deterministic, grep-friendly scan progress.
    #[arg(long, conflicts_with = "json")]
    pub(crate) ci: bool,
    /// Investigate only the named shard from `<target>/.kuzushi/shards.toml`.
    #[arg(long)]
    pub(crate) shard: Option<String>,
    /// Shard manifest file to resolve `--shard` against.
    #[arg(long, requires = "shard")]
    pub(crate) shard_manifest: Option<PathBuf>,
    /// Restrict the investigation to workspace-relative path roots.
    #[arg(long, value_delimiter = ',', conflicts_with = "shard")]
    pub(crate) paths: Vec<String>,
    /// Exit with code 3 when a finding at or above this severity is recorded.
    #[arg(long, value_enum)]
    pub(crate) fail_on: Option<FailOnArg>,
    /// Write a SARIF 2.1.0 export for findings observed by this investigation.
    #[arg(long)]
    pub(crate) sarif: Option<PathBuf>,
}
