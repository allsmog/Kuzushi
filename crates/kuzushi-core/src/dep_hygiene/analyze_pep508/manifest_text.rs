use super::*;

pub(in crate::dep_hygiene) fn canonical_directory(target: &Path) -> Result<PathBuf> {
    if !target.exists() {
        anyhow::bail!("dep-hygiene: target does not exist: {}", target.display());
    }
    let canonical = fs::canonicalize(target)
        .with_context(|| format!("dep-hygiene: failed to resolve {}", target.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "dep-hygiene: target is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

pub(in crate::dep_hygiene) fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    if eq == 0 {
        return None;
    }
    Some((line[..eq].trim(), line[eq + 1..].trim()))
}

pub(in crate::dep_hygiene) fn quoted_list_entry(line: &str) -> Option<&str> {
    let body = line.strip_prefix('"')?;
    let body = body.strip_suffix(',').unwrap_or(body).trim_end();
    body.strip_suffix('"')
}

pub(in crate::dep_hygiene) fn clean_quoted_constraint(value: &str) -> String {
    let mut value = value.trim();
    value = value.strip_suffix(',').unwrap_or(value).trim_end();
    value = value.strip_prefix('"').unwrap_or(value);
    value = value.strip_suffix('"').unwrap_or(value);
    value.trim().to_string()
}
pub(in crate::dep_hygiene) fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
