use super::{digest_serializable, sorted_directory_entries};
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

pub(super) fn executable_identities(input: &Value) -> Result<Vec<Value>> {
    executable_names(input)
        .into_iter()
        .map(executable_identity)
        .collect()
}

fn executable_names(input: &Value) -> BTreeSet<&'static str> {
    if automatic_selection(input) {
        return external_engine_names().into_iter().collect();
    }
    let mut names = selected_tasks(input)
        .into_iter()
        .filter_map(external_engine_for_task)
        .collect::<BTreeSet<_>>();
    if let Some(name) = input
        .get("backend")
        .and_then(Value::as_str)
        .and_then(external_engine_for_backend)
    {
        names.insert(name);
    }
    names
}

fn external_engine_names() -> [&'static str; 5] {
    ["semgrep", "codeql", "govulncheck", "cargo-audit", "joern"]
}

fn external_engine_for_task(task: &str) -> Option<&'static str> {
    external_engine_names().into_iter().find(|engine| {
        task == *engine
            || task
                .strip_prefix(*engine)
                .is_some_and(|suffix| suffix == ":scan")
    })
}

fn external_engine_for_backend(backend: &str) -> Option<&'static str> {
    match backend {
        "semgrep" => Some("semgrep"),
        "codeql" => Some("codeql"),
        "joern" => Some("joern"),
        _ => None,
    }
}

fn selected_tasks(input: &Value) -> BTreeSet<&str> {
    input
        .get("tasks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn executable_identity(name: &str) -> Result<Value> {
    let Some(path) = crate::process_lookup::executable_on_path(name) else {
        return Ok(json!({"name": name, "status": "missing"}));
    };
    let canonical = std::fs::canonicalize(&path)
        .with_context(|| format!("could not canonicalize scan engine {}", path.display()))?;
    Ok(json!({
        "name": name,
        "path": canonical,
        "sha256": digest_regular_file(&canonical)?,
    }))
}

pub(super) fn engine_cache_identity(root: &Path, input: &Value) -> Result<Option<String>> {
    let mut caches = Map::new();
    if selects_codeql_cache(input) {
        caches.insert("codeqlDatabase".to_string(), codeql_cache_identity(root)?);
    }
    if selects_cpg_cache(input) {
        caches.insert(
            "cpgRs".to_string(),
            json!(cache_tree_identity(&kuzushi_cpg::artifact_dir(root))?),
        );
    }
    (!caches.is_empty())
        .then(|| digest_serializable(&caches))
        .transpose()
}

fn codeql_cache_identity(root: &Path) -> Result<Value> {
    let identity = crate::codeql_repository_execution::resolve_managed_codeql_database(root)?
        .map(|database| database.database_identity().to_string())
        .unwrap_or_else(|| "missing".to_string());
    Ok(json!(identity))
}

fn selects_codeql_cache(input: &Value) -> bool {
    automatic_selection(input)
        || selected_tasks(input)
            .iter()
            .any(|task| task.contains("codeql"))
        || input.get("backend").and_then(Value::as_str) == Some("codeql")
}

fn selects_cpg_cache(input: &Value) -> bool {
    automatic_selection(input)
        || matches!(
            input.get("backend").and_then(Value::as_str),
            Some("cpg" | "cpg-rs")
        )
}

fn automatic_selection(input: &Value) -> bool {
    input.get("taskMode").and_then(Value::as_str) != Some("manual")
}

fn cache_tree_identity(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok("missing".to_string());
    }
    let mut rows = Vec::new();
    collect_cache_rows(path, path, &mut rows)?;
    rows.sort();
    digest_serializable(&rows)
}

fn collect_cache_rows(root: &Path, path: &Path, rows: &mut Vec<(String, String)>) -> Result<()> {
    for entry in sorted_directory_entries(path)? {
        let file_type = entry.file_type()?;
        anyhow::ensure!(
            !file_type.is_symlink(),
            "engine cache must not contain symlinks"
        );
        if file_type.is_dir() {
            collect_cache_rows(root, &entry.path(), rows)?;
            continue;
        }
        anyhow::ensure!(file_type.is_file(), "engine cache contains a special file");
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .into_owned();
        rows.push((relative, digest_regular_file(&entry.path())?));
    }
    Ok(())
}

fn digest_regular_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("could not read engine identity input {}", path.display()))?;
    let before = file.metadata()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    anyhow::ensure!(
        before.len() == file.metadata()?.len(),
        "engine input changed while hashing"
    );
    let hex = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_aliases_and_backends_select_external_engine_receipts() {
        let selected = executable_names(&json!({
            "taskMode": "manual",
            "tasks": ["semgrep:scan", "cargo-audit:scan"],
            "backend": "joern"
        }));

        assert_eq!(
            selected,
            BTreeSet::from(["cargo-audit", "joern", "semgrep"])
        );
    }
}
