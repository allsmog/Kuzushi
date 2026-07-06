use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct PrCommentArgs {
    #[arg(long, help = crate::support::TARGET_HELP)]
    pub(crate) target: Option<PathBuf>,
    /// Repository slug or URL to include in the generated comment context.
    #[arg(long)]
    pub(crate) repo: Option<String>,
    /// CI or workflow run URL to include in the generated comment context.
    #[arg(long)]
    pub(crate) run_url: Option<String>,
    /// Maximum number of findings to include.
    #[arg(long, default_value_t = 10)]
    pub(crate) top_n: usize,
    /// Changed file paths to prioritize in the comment. Comma- or repeat-separated.
    #[arg(long, value_delimiter = ',')]
    pub(crate) changed_files: Vec<String>,
    /// Run id whose artifacts should anchor the comment.
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    /// Model label to include as provenance in the comment.
    #[arg(long)]
    pub(crate) model: Option<String>,
    /// Git commit SHA to include as provenance in the comment.
    #[arg(long)]
    pub(crate) git_sha: Option<String>,
}
