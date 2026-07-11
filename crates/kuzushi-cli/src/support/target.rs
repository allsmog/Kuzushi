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
            "{command} needs a target (an explicit target is required). {} Bug-bounty workflows require explicit scope.",
            target_recovery(command)
        )
    })
}

fn target_recovery(command: &str) -> String {
    if command == "scan" {
        return "Run `kuzushi scan <path>` (or put the global option before the command: `kuzushi --target <path> scan`); use `kuzushi scan .` for the current directory."
            .to_string();
    }
    format!(
        "Put the global option before the command: `kuzushi --target <path> {command} ...` (or `kuzushi --target . {command} ...` for the current directory)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_target_recovery_uses_parser_valid_placements() {
        let recovery = target_recovery("scan");

        assert!(recovery.contains("kuzushi scan <path>"), "{recovery}");
        assert!(
            recovery.contains("kuzushi --target <path> scan"),
            "{recovery}"
        );
        assert!(!recovery.contains("kuzushi scan --target"), "{recovery}");
    }
}
