use anyhow::{Context, Result};
use std::{fs, path::Path};

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
    fs::read_to_string(&path)
        .with_context(|| format!("Could not read {key} from {}", path.display()))
}

pub(crate) fn looks_like_prompt_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.ends_with(".md")
        || value.ends_with(".txt")
        || value.ends_with(".prompt")
}
