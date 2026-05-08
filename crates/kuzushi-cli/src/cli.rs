use crate::command::Command;
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "kuzushi")]
#[command(about = "Kuzushi security-native code agent", version)]
pub(crate) struct Cli {
    #[arg(long, global = true)]
    pub(crate) target: Option<PathBuf>,
    /// Force line-oriented output with no ANSI, animation, or box drawing.
    #[arg(long, global = true)]
    pub(crate) plain: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}
