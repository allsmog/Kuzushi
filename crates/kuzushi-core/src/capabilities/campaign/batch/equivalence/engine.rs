use super::digest_serializable;
use super::input_snapshot::{self, InputBudget, MAX_ENGINE_FILE_BYTES};
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn executable_identities(input: &Value, budget: &mut InputBudget) -> Result<Vec<Value>> {
    executable_names(input)
        .into_iter()
        .map(|name| executable_identity(name, input, budget))
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

fn executable_identity(name: &str, input: &Value, budget: &mut InputBudget) -> Result<Value> {
    let binary = configured_binary(name, input);
    let Some(path) = resolve_executable(binary) else {
        return Ok(json!({"name": name, "status": "missing"}));
    };
    let canonical = std::fs::canonicalize(&path)
        .with_context(|| format!("could not canonicalize scan engine {}", path.display()))?;
    Ok(json!({
        "name": name,
        "path": canonical,
        "sha256": input_snapshot::executable_digest(&canonical, budget)?,
    }))
}

fn configured_binary<'a>(name: &'a str, input: &'a Value) -> &'a str {
    if name == "semgrep" {
        return input
            .get("semgrepBinary")
            .and_then(Value::as_str)
            .unwrap_or(name);
    }
    name
}

fn resolve_executable(binary: &str) -> Option<std::path::PathBuf> {
    let path = Path::new(binary);
    if path.components().count() > 1 {
        return path.is_file().then(|| path.to_path_buf());
    }
    crate::process_lookup::executable_on_path(binary)
}

pub(super) fn engine_cache_identity(
    root: &Path,
    input: &Value,
    budget: &mut InputBudget,
) -> Result<Option<String>> {
    let mut caches = Map::new();
    if selects_codeql_cache(input) {
        caches.insert("codeqlDatabase".to_string(), codeql_cache_identity(root)?);
    }
    if selects_cpg_cache(input) {
        caches.insert(
            "cpgRs".to_string(),
            json!(cache_tree_identity(
                &kuzushi_cpg::artifact_dir(root),
                budget
            )?),
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

fn cache_tree_identity(path: &Path, budget: &mut InputBudget) -> Result<String> {
    let rows = input_snapshot::optional_tree_rows(path, path, budget, MAX_ENGINE_FILE_BYTES)?;
    rows.map_or_else(|| Ok("missing".into()), |rows| digest_serializable(&rows))
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

    #[test]
    fn configured_semgrep_executable_is_bound_to_its_actual_bytes() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("operator-semgrep");
        std::fs::write(&binary, "labeled version one").unwrap();
        let input = json!({"taskMode":"manual","tasks":["semgrep"],"semgrepBinary":binary});
        let first = executable_identities(&input, &mut InputBudget::default()).unwrap();
        assert_eq!(
            first[0]["path"],
            json!(std::fs::canonicalize(&binary).unwrap())
        );
        std::fs::write(&binary, "labeled version two").unwrap();
        let second = executable_identities(&input, &mut InputBudget::default()).unwrap();
        assert_ne!(first[0]["sha256"], second[0]["sha256"]);
    }

    #[test]
    fn changed_configured_executable_refuses_a_frozen_child_before_execution() {
        use crate::capabilities::campaign::{
            compile_scan_batch_plan, verify_scan_batch_child_equivalence, ScanBatchGatePolicy,
            ScanBatchPlanSpec,
        };
        let target = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let binary = tools.path().join("operator-semgrep");
        std::fs::write(&binary, "owned version one").unwrap();
        let config = crate::V2Config::default();
        let registry = crate::modules::ModuleRegistry::with_v2_builtins();
        let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
            root: target.path(), batch_id: Some("engine-drift".into()), trials: 2,
            requested_workers: 1, gate_policy: ScanBatchGatePolicy::default(),
            prepared_input: json!({"taskMode":"manual","tasks":["semgrep"],"semgrepBinary":binary,"threatModelRef":null}),
            config: &config, registry: &registry,
        }).unwrap();
        let document: Value =
            serde_json::from_slice(&std::fs::read(handle.plan_path).unwrap()).unwrap();
        let input = &document["jobs"][0]["input"];
        assert!(verify_scan_batch_child_equivalence(
            target.path(),
            "first",
            input,
            &config,
            &registry
        )
        .unwrap()
        .is_some());
        std::fs::write(&binary, "owned version two").unwrap();
        let error =
            verify_scan_batch_child_equivalence(target.path(), "second", input, &config, &registry)
                .unwrap_err();
        assert!(
            error.to_string().contains("BatchEquivalenceKey drift"),
            "{error}"
        );
        assert!(!target
            .path()
            .join(".kuzushi/v3/campaigns/engine-drift/queue.json")
            .exists());
    }
}
