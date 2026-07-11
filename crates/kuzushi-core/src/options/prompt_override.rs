use anyhow::{Context, Result};
use std::path::Path;

pub(crate) const MAX_PROMPT_OVERRIDE_BYTES: usize = 1024 * 1024;

pub fn prompt_content_sha256(value: &str) -> String {
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(value.as_bytes())
    )
}

pub(crate) fn resolve_prompt_override_for_key(
    value: &str,
    cwd: &Path,
    key: &str,
) -> Result<String> {
    if !looks_like_prompt_path(value) {
        return Ok(value.to_string());
    }

    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    read_workspace_prompt_file(cwd, &path)
        .with_context(|| format!("Could not read {key} from {}", path.display()))
}

pub(crate) fn read_workspace_prompt_file(
    workspace: &Path,
    path: &Path,
) -> std::io::Result<String> {
    crate::bounded_file::read_utf8_text_within(workspace, path, MAX_PROMPT_OVERRIDE_BYTES)
}

pub(crate) fn looks_like_prompt_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || (!value.chars().any(char::is_whitespace)
            && (value.ends_with(".md") || value.ends_with(".txt") || value.ends_with(".prompt")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn explicit_prompt_path_cannot_follow_outside_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.txt");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(&outside, "outside secret").unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join("prompt.md")).unwrap();

        let error = resolve_prompt_override_for_key("prompt.md", &workspace, "TEST_PROMPT")
            .unwrap_err();

        assert!(!format!("{error:#}").contains("outside secret"));
    }

    #[test]
    fn prose_ending_in_a_file_extension_remains_inline() {
        assert!(!looks_like_prompt_path(
            "Focus on the flow described in design.md"
        ));
        assert!(looks_like_prompt_path("design.md"));
        assert!(looks_like_prompt_path("./design doc.md"));
    }
}
