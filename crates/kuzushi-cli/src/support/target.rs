use anyhow::Result;
use std::path::PathBuf;

pub(crate) const TARGET_HELP: &str =
    "Workspace/repository target; pass `.` to explicitly use the current directory.";

pub(crate) fn target_or_global(
    command_target: Option<PathBuf>,
    global_target: Option<PathBuf>,
) -> Option<PathBuf> {
    command_target.or(global_target)
}

pub(crate) fn require_cli_target(
    command: &str,
    command_target: Option<PathBuf>,
    global_target: Option<PathBuf>,
) -> Result<PathBuf> {
    target_or_global(command_target, global_target).ok_or_else(|| {
        anyhow::anyhow!(
            "{command} needs a target (an explicit target is required): pass `--target <path>` (or `--target .` to use the current directory). Bug-bounty workflows require explicit scope."
        )
    })
}
