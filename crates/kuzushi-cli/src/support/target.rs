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

pub(crate) fn resolve_cli_target(
    command_target: Option<PathBuf>,
    global_target: Option<PathBuf>,
) -> Result<Option<PathBuf>> {
    if let (Some(command), Some(global)) = (&command_target, &global_target) {
        if !same_target(command, global) {
            anyhow::bail!(
                "conflicting targets: command target {} differs from global --target {}. Pass one target, or pass the same target in both places.",
                command.display(),
                global.display(),
            );
        }
    }
    Ok(target_or_global(command_target, global_target))
}

fn same_target(left: &std::path::Path, right: &std::path::Path) -> bool {
    left == right
        || std::fs::canonicalize(left)
            .and_then(|left| std::fs::canonicalize(right).map(|right| left == right))
            .unwrap_or(false)
}

pub(crate) fn require_cli_target(
    command: &str,
    command_target: Option<PathBuf>,
    global_target: Option<PathBuf>,
) -> Result<PathBuf> {
    resolve_cli_target(command_target, global_target)?.ok_or_else(|| {
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

    #[test]
    fn conflicting_global_and_command_targets_are_rejected() {
        let error = require_cli_target(
            "scan",
            Some(PathBuf::from("/tmp/kuzushi-command-target")),
            Some(PathBuf::from("/tmp/kuzushi-global-target")),
        )
        .expect_err("two different target controls must not silently select one");

        assert!(error.to_string().contains("conflicting targets"), "{error}");
        assert!(error.to_string().contains("--target"), "{error}");
    }

    #[test]
    fn equivalent_global_and_command_targets_are_accepted() {
        let target = tempfile::tempdir().unwrap();
        let command = target.path().join(".");
        let global = target.path().to_path_buf();

        let resolved = require_cli_target("scan", Some(command.clone()), Some(global)).unwrap();

        assert_eq!(resolved, command);
    }
}
