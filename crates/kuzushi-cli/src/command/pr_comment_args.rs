use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct PrCommentArgs {
    #[arg(long)]
    pub(crate) target: Option<PathBuf>,
    #[arg(long)]
    pub(crate) repo: Option<String>,
    #[arg(long)]
    pub(crate) run_url: Option<String>,
    #[arg(long, default_value_t = 10)]
    pub(crate) top_n: usize,
    #[arg(long, value_delimiter = ',')]
    pub(crate) changed_files: Vec<String>,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long)]
    pub(crate) model: Option<String>,
    #[arg(long)]
    pub(crate) git_sha: Option<String>,
}
