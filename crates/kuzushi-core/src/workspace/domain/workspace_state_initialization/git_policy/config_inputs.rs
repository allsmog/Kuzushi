use super::command::{command_failure, git_output};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(super) fn config_policy_inputs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = config_origin_paths(root)?;
    paths.extend(declared_include_paths(root)?);
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn config_origin_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let output = git_output(
        root,
        &[
            "config",
            "--includes",
            "--show-origin",
            "--name-only",
            "--null",
            "--list",
        ],
        "Git config origin lookup",
    )?;
    anyhow::ensure!(
        output.status.success(),
        "Could not enumerate Git config origins: {}",
        command_failure(&output)
    );
    parse_pairs(&output.stdout, "Git config origin output")?
        .into_iter()
        .filter_map(|(origin, _)| origin_file(root, origin).transpose())
        .collect()
}

fn declared_include_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let output = git_output(
        root,
        &[
            "config",
            "--includes",
            "--show-origin",
            "--null",
            "--path",
            "--get-regexp",
            "^include.*\\.path$",
        ],
        "Git config include lookup",
    )?;
    match output.status.code() {
        Some(0) => parse_include_paths(root, &output.stdout),
        Some(1) => Ok(Vec::new()),
        _ => anyhow::bail!(
            "Could not enumerate Git config includes: {}",
            command_failure(&output)
        ),
    }
}

fn parse_include_paths(root: &Path, bytes: &[u8]) -> Result<Vec<PathBuf>> {
    parse_pairs(bytes, "Git config include output")?
        .into_iter()
        .map(|(origin, entry)| resolve_include_path(root, origin, entry))
        .collect()
}

fn resolve_include_path(root: &Path, origin: &[u8], entry: &[u8]) -> Result<PathBuf> {
    let separator = entry
        .iter()
        .position(|byte| *byte == b'\n')
        .context("Git config include output did not contain a path value")?;
    let value = &entry[separator + 1..];
    let value = std::str::from_utf8(value).context("Git returned a non-UTF-8 include path")?;
    anyhow::ensure!(!value.is_empty(), "Git returned an empty include path");
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Ok(path);
    }
    let base = origin_file(root, origin)?
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| root.to_path_buf());
    Ok(base.join(path))
}

fn origin_file(root: &Path, origin: &[u8]) -> Result<Option<PathBuf>> {
    let Some(path) = origin.strip_prefix(b"file:") else {
        return Ok(None);
    };
    let path = std::str::from_utf8(path).context("Git returned a non-UTF-8 config origin")?;
    anyhow::ensure!(!path.is_empty(), "Git returned an empty config origin");
    let path = PathBuf::from(path);
    Ok(Some(if path.is_absolute() {
        path
    } else {
        root.join(path)
    }))
}

fn parse_pairs<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<(&'a [u8], &'a [u8])>> {
    let mut fields = bytes.split(|byte| *byte == b'\0').collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    anyhow::ensure!(
        fields.len() % 2 == 0,
        "{label} contained an incomplete origin/value pair"
    );
    Ok(fields
        .chunks_exact(2)
        .map(|pair| (pair[0], pair[1]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_include_resolves_from_its_origin_file() {
        let path = resolve_include_path(
            Path::new("/workspace"),
            b"file:/repo/.git/config",
            b"include.path\npolicy.inc",
        )
        .unwrap();

        assert_eq!(path, Path::new("/repo/.git/policy.inc"));
    }

    #[test]
    fn malformed_pair_stream_is_rejected() {
        let error = parse_pairs(b"file:/repo/config\0key\0orphan\0", "fixture")
            .unwrap_err()
            .to_string();

        assert!(error.contains("incomplete"), "{error}");
    }
}
