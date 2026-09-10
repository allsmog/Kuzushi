use super::*;
use crate::review_yield::domain::canonical_json_bytes;
use serde_json::Map;

mod engine;

use engine::{engine_cache_identity, executable_identities};

const MAX_EQUIVALENCE_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub fn capture_batch_equivalence(
    root: &Path,
    base_input: &Value,
    config: &V2Config,
    registry: &ModuleRegistry,
) -> Result<BatchEquivalenceKey> {
    let components = equivalence_components(root, base_input, config, registry)?;
    let sha256 = digest_serializable(&components)?;
    Ok(BatchEquivalenceKey { sha256, components })
}

pub fn scan_batch_base_input(mut input: Value) -> Value {
    let Some(object) = input.as_object_mut() else {
        return input;
    };
    for key in volatile_scan_keys() {
        object.remove(key);
    }
    input
}

pub(in crate::capabilities::campaign) fn force_discovery_only(input: &mut Value) -> Result<()> {
    let object = input
        .as_object_mut()
        .context("prepared sast:scan input must be an object")?;
    for key in ["triage", "verify", "autoPatch"] {
        object.insert(key.to_string(), Value::Bool(false));
    }
    Ok(())
}

fn volatile_scan_keys() -> [&'static str; 10] {
    [
        "runId",
        "run_id",
        "batchId",
        "batch_id",
        "trial",
        "batchEquivalenceKey",
        "batch_equivalence_key",
        "threatModelRef",
        "threat_model_ref",
        "logicalTrialId",
    ]
}

fn equivalence_components(
    root: &Path,
    base_input: &Value,
    config: &V2Config,
    registry: &ModuleRegistry,
) -> Result<BatchEquivalenceComponents> {
    let model = crate::tool_execution_model(SCAN_TOOL, base_input, config);
    Ok(BatchEquivalenceComponents {
        prepared_input_sha256: digest_serializable(base_input)?,
        workspace_identity: crate::incremental_index::current_workspace_resume_identity(root)
            .context("could not freeze the scan-batch worktree identity")?,
        target_git: crate::workspace::target_git_metadata(root),
        config_sha256: crate::config_hash(config)?,
        descriptor_set_sha256: descriptor_set_sha256(registry)?,
        loaded_modules: registry.loaded_module_specifiers(),
        runtime_identity: runtime_identity(config, model.as_deref())?,
        model,
        threat_model: bound_threat_model_ref(root, base_input)?,
        prompt_overrides_sha256: directory_digest(root, ".kuzushi/prompts")?,
        house_rules_sha256: directory_digest(root, ".kuzushi/house-rules")?,
        scope_sha256: scope_sha256(root, base_input)?,
        engine_identity: engine_identity(root, base_input)?,
    })
}

fn engine_identity(root: &Path, input: &Value) -> Result<BatchEngineIdentity> {
    Ok(BatchEngineIdentity {
        kuzushi_version: env!("CARGO_PKG_VERSION").to_string(),
        requested_selection: json!({
            "taskMode": input.get("taskMode").or_else(|| input.get("task_mode")),
            "tasks": input.get("tasks"),
            "mode": input.get("mode"),
            "executables": executable_identities(input)?,
        }),
        cache_identity: engine_cache_identity(root, input)?,
    })
}

fn runtime_identity(config: &V2Config, model: Option<&str>) -> Result<BatchRuntimeIdentity> {
    let backend = serde_json::to_value(config.runtime.kind)?
        .as_str()
        .context("runtime kind did not serialize as a string")?
        .to_string();
    Ok(BatchRuntimeIdentity {
        backend,
        provider: model
            .and_then(|value| value.split_once(':'))
            .map(|(provider, _)| provider.to_string()),
        config_sha256: digest_serializable(&config.runtime)?,
    })
}

fn descriptor_set_sha256(registry: &ModuleRegistry) -> Result<String> {
    digest_serializable(&registry.tools().cloned().collect::<Vec<_>>())
}

fn bound_threat_model_ref(root: &Path, input: &Value) -> Result<Option<Value>> {
    if let Some(bound) = input.get("threatModelRef").filter(|value| !value.is_null()) {
        let expected: crate::capabilities::threat_model::ThreatModelRef =
            serde_json::from_value(bound.clone()).context("invalid bound threatModelRef")?;
        crate::capabilities::threat_model::load_exact_threat_model(root, &expected)?;
        return Ok(Some(bound.clone()));
    }
    Ok(None)
}

fn scope_sha256(root: &Path, input: &Value) -> Result<String> {
    let mut scope = Map::new();
    for key in ["paths", "shard", "scope", "scopeFile", "since"] {
        if let Some(value) = input.get(key) {
            scope.insert(key.to_string(), value.clone());
        }
    }
    if let Some(binding) = bound_model_scope(root, input)? {
        scope.insert(
            "threatModelScope".to_string(),
            serde_json::to_value(binding)?,
        );
    }
    scope.insert(
        "projectDecomposition".to_string(),
        serde_json::to_value(crate::workspace::load_nested_project_scopes(root)?)?,
    );
    digest_serializable(&scope)
}

fn bound_model_scope(
    root: &Path,
    input: &Value,
) -> Result<Option<crate::capabilities::threat_model::ScopeRef>> {
    let Some(bound) = input.get("threatModelRef").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let model_ref: crate::capabilities::threat_model::ThreatModelRef =
        serde_json::from_value(bound.clone()).context("invalid bound threatModelRef")?;
    let manifest = crate::capabilities::threat_model::load_threat_model_manifest(root)?
        .context("bound threat model has no manifest")?;
    manifest
        .models
        .into_iter()
        .find(|model| model.model_id == model_ref.model_id)
        .map(|model| model.scope)
        .context("bound threat model lineage is absent from the manifest")
        .map(Some)
}

fn directory_digest(root: &Path, relative: &str) -> Result<String> {
    let path = root.join(relative);
    if !path.exists() {
        return digest_serializable(&Vec::<(String, String)>::new());
    }
    let mut rows = Vec::new();
    collect_digest_rows(root, &path, &mut rows)?;
    rows.sort();
    digest_serializable(&rows)
}

fn collect_digest_rows(root: &Path, path: &Path, rows: &mut Vec<(String, String)>) -> Result<()> {
    for entry in sorted_directory_entries(path)? {
        collect_digest_row(root, entry, rows)?;
    }
    Ok(())
}

fn collect_digest_row(
    root: &Path,
    entry: std::fs::DirEntry,
    rows: &mut Vec<(String, String)>,
) -> Result<()> {
    let child = entry.path();
    let file_type = entry.file_type()?;
    anyhow::ensure!(
        !file_type.is_symlink(),
        "equivalence input {} must not be a symlink",
        child.display()
    );
    if file_type.is_dir() {
        return collect_digest_rows(root, &child, rows);
    }
    anyhow::ensure!(
        file_type.is_file(),
        "unsupported equivalence input {}",
        child.display()
    );
    rows.push(digest_file_row(root, &child, entry.metadata()?.len())?);
    Ok(())
}

fn sorted_directory_entries(path: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = std::fs::read_dir(path)
        .with_context(|| format!("could not read equivalence input {}", path.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(entries)
}

fn digest_file_row(root: &Path, path: &Path, size: u64) -> Result<(String, String)> {
    anyhow::ensure!(
        size <= MAX_EQUIVALENCE_FILE_BYTES,
        "equivalence input {} exceeds {} bytes",
        path.display(),
        MAX_EQUIVALENCE_FILE_BYTES
    );
    let bytes = std::fs::read(path)
        .with_context(|| format!("could not read equivalence input {}", path.display()))?;
    let relative = path.strip_prefix(root)?.to_string_lossy().into_owned();
    Ok((
        relative,
        crate::run_lifecycle::sha256_content_digest(&bytes),
    ))
}

pub(in crate::capabilities::campaign) fn digest_serializable(value: &impl Serialize) -> Result<String> {
    let bytes = canonical_json_bytes(value)?;
    Ok(crate::run_lifecycle::sha256_content_digest(&bytes))
}
