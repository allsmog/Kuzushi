use anyhow::{Context, Result};
use std::path::Path;

/// Maximum UTF-8 bytes accepted from a raw inline or workspace prompt override
/// before immutable policy and untrusted-record framing are added.
pub const MAX_PROMPT_OVERRIDE_BYTES: usize = 64 * 1024;

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
    validate_prompt_override_size(value, key)?;
    if !looks_like_prompt_path(value) {
        return Ok(value.to_string());
    }

    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    read_workspace_prompt_file(cwd, &path).with_context(|| prompt_file_read_context(key, &path))
}

pub(crate) fn resolve_prepared_prompt_override_for_key(
    value: &str,
    cwd: &Path,
    key: &str,
    default_content: &str,
) -> Result<String> {
    if crate::prompts::boundaries::is_composed_target_prompt_context(default_content, value) {
        return Ok(value.to_string());
    }
    resolve_prompt_override_for_key(value, cwd, key)
}

pub(crate) fn prompt_file_read_context(key: &str, path: &Path) -> String {
    format!(
        "Could not read {key} from {} within the raw prompt limit of {MAX_PROMPT_OVERRIDE_BYTES} bytes",
        path.display()
    )
}

pub(crate) fn validate_prompt_override_size(value: &str, key: &str) -> Result<()> {
    if value.len() > MAX_PROMPT_OVERRIDE_BYTES {
        anyhow::bail!("{key} exceeds the raw prompt limit of {MAX_PROMPT_OVERRIDE_BYTES} bytes");
    }
    Ok(())
}

pub(crate) fn read_workspace_prompt_file(workspace: &Path, path: &Path) -> std::io::Result<String> {
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

        let error =
            resolve_prompt_override_for_key("prompt.md", &workspace, "TEST_PROMPT").unwrap_err();

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

    #[test]
    fn raw_inline_prompt_limit_is_inclusive_and_names_the_option() {
        let workspace = tempfile::tempdir().unwrap();
        let at_limit = "x".repeat(MAX_PROMPT_OVERRIDE_BYTES);

        assert_eq!(
            resolve_prompt_override_for_key(&at_limit, workspace.path(), "TEST_PROMPT").unwrap(),
            at_limit
        );
        let error = resolve_prompt_override_for_key(
            &"x".repeat(MAX_PROMPT_OVERRIDE_BYTES + 1),
            workspace.path(),
            "TEST_PROMPT",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("TEST_PROMPT"), "{error}");
        assert!(
            error.contains(&MAX_PROMPT_OVERRIDE_BYTES.to_string()),
            "{error}"
        );
    }

    #[test]
    fn workspace_prompt_file_limit_is_inclusive() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("prompt.md");
        std::fs::write(&path, "x".repeat(MAX_PROMPT_OVERRIDE_BYTES)).unwrap();

        assert_eq!(
            read_workspace_prompt_file(workspace.path(), &path)
                .unwrap()
                .len(),
            MAX_PROMPT_OVERRIDE_BYTES
        );
        std::fs::write(&path, "x".repeat(MAX_PROMPT_OVERRIDE_BYTES + 1)).unwrap();
        let error = read_workspace_prompt_file(workspace.path(), &path).unwrap_err();

        assert!(error
            .to_string()
            .contains(&MAX_PROMPT_OVERRIDE_BYTES.to_string()));
    }

    #[test]
    fn prepared_envelope_is_idempotent_but_cannot_hide_oversized_content() {
        let workspace = tempfile::tempdir().unwrap();
        let builtin = "IMMUTABLE";
        let at_limit = crate::prompts::compose_target_prompt_context(
            builtin,
            "review.md",
            &"x".repeat(MAX_PROMPT_OVERRIDE_BYTES),
        );

        assert_eq!(
            resolve_prepared_prompt_override_for_key(
                &at_limit,
                workspace.path(),
                "TEST_PROMPT",
                builtin,
            )
            .unwrap(),
            at_limit
        );
        let oversized = crate::prompts::compose_target_prompt_context(
            builtin,
            "review.md",
            &"x".repeat(MAX_PROMPT_OVERRIDE_BYTES + 1),
        );
        let error = resolve_prepared_prompt_override_for_key(
            &oversized,
            workspace.path(),
            "TEST_PROMPT",
            builtin,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("TEST_PROMPT"), "{error}");
        assert!(
            error.contains(&MAX_PROMPT_OVERRIDE_BYTES.to_string()),
            "{error}"
        );
    }
}
