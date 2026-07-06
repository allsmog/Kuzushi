use crate::command::Command;
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "kuzushi")]
// Provenance-bearing version (`0.24.0 (sha+dirty · profile)`) so a published
// release binary and a working-tree build are distinguishable at a glance.
#[command(about = "Kuzushi security-native code agent", version = kuzushi_tui::build_version_static())]
pub(crate) struct Cli {
    #[arg(long, global = true, help = crate::support::TARGET_HELP)]
    pub(crate) target: Option<PathBuf>,
    /// Force line-oriented output with no ANSI, animation, or box drawing.
    #[arg(long, global = true)]
    pub(crate) plain: bool,
    /// Load a trusted dynamic JS module specifier (file://, path, or package:<name>).
    #[arg(long, global = true)]
    pub(crate) load: Vec<String>,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}
