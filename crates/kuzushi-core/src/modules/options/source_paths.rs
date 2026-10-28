//! Exact, bounded file selections shared by Review and lesson input.
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

pub(crate) fn selected_source_paths(input: &Value) -> Result<Vec<String>> {
    let Some(value) = input.get("sourceEvidenceFiles") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .context("sourceEvidenceFiles must be a list of exact paths")?;
    anyhow::ensure!(items.len() <= 16, "Select at most 16 supporting files");
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for item in items {
        let path = item
            .as_str()
            .context("Supporting file paths must be text")?;
        validate_path(path)?;
        anyhow::ensure!(
            seen.insert(path),
            "Supporting files contain a duplicate path"
        );
        paths.push(path.to_string());
    }
    Ok(paths)
}

fn validate_path(path: &str) -> Result<()> {
    anyhow::ensure!(
        !path.is_empty() && path.len() <= 4096,
        "Supporting paths must contain 1 to 4096 bytes"
    );
    anyhow::ensure!(
        !path.contains('\\') && !path.chars().any(char::is_control),
        "Supporting paths must use forward slashes and contain no control characters"
    );
    let parsed = Path::new(path);
    anyhow::ensure!(
        parsed
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "Supporting files must be exact repository-relative paths without traversal"
    );
    anyhow::ensure!(
        parsed.components().collect::<PathBuf>().to_string_lossy() == path,
        "Supporting file paths must be normalized"
    );
    Ok(())
}
