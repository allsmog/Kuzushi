use super::prelude::*;
use super::*;

pub(crate) fn read_methodology(input: &Value, fallback: &str) -> String {
    read_string(input, &["methodology", "type"])
        .map(|value| value.to_lowercase())
        .filter(|value| VALID_METHODOLOGIES.contains(&value.as_str()))
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn read_string(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(crate) fn read_bool(input: &Value, keys: &[&str], fallback: bool) -> bool {
    keys.iter()
        .find_map(|key| input.get(*key).and_then(Value::as_bool))
        .unwrap_or(fallback)
}

pub(crate) fn read_usize(input: &Value, keys: &[&str], fallback: usize, min: usize) -> usize {
    let value = keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .or_else(|| {
                input
                    .get(*key)
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<usize>().ok())
            })
    });
    value.filter(|value| *value >= min).unwrap_or(fallback)
}

pub(crate) fn repo_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("repo")
        .to_string()
}

pub(crate) fn inventory_files(root: &Path, limit: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    collect_inventory(root, root, limit, &mut out)?;
    if out.is_empty() {
        out.push("(no files found)".to_string());
    }
    Ok(out)
}

pub(crate) fn collect_inventory(
    root: &Path,
    dir: &Path,
    limit: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    if out.len() >= limit {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if out.len() >= limit {
            break;
        }
        let name = entry.file_name();
        if should_skip_path(&name.to_string_lossy()) {
            continue;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_inventory(root, &path, limit, out)?;
        } else if file_type.is_file() {
            out.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }
    Ok(())
}
