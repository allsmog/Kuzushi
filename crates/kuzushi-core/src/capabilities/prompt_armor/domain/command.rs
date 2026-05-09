use std::path::{Path, PathBuf};

pub(crate) fn command_from_tool_name(tool_name: &str) -> &str {
    tool_name.trim_start_matches("prompt-armor:")
}

pub(crate) fn requires_authorization(command: &str) -> bool {
    matches!(command, "scan" | "attack")
}

pub(crate) fn output_dir(target: &Path) -> PathBuf {
    target.join(".prompt-armor")
}
