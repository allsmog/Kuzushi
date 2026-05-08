use super::prelude::*;
use super::*;

pub(crate) fn default_context_snapshot_view(snapshot_path: Option<PathBuf>) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path,
        exists: false,
        status: "missing. Next: context build".to_string(),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
    }
}

pub(crate) fn default_workspace_view(target: Option<&WorkspaceTarget>) -> WorkspaceView {
    match target {
        Some(workspace) => WorkspaceView {
            root: Some(workspace.root().to_path_buf()),
            state_dir: Some(workspace.state_dir()),
            findings_db: Some(workspace.findings_db_path()),
            findings_count: None,
            last_export: None,
            status: "workspace ready. Next: workspace status".to_string(),
        },
        None => WorkspaceView {
            root: None,
            state_dir: None,
            findings_db: None,
            findings_count: None,
            last_export: None,
            status: "no active workspace. Next: scan <target> or start shell with --target ."
                .to_string(),
        },
    }
}

pub(crate) fn load_context_snapshot_view(snapshot_path: PathBuf) -> Result<ContextSnapshotView> {
    if !snapshot_path.exists() {
        return Ok(default_context_snapshot_view(Some(snapshot_path)));
    }

    let body = fs::read_to_string(&snapshot_path)
        .with_context(|| format!("Could not read {}", snapshot_path.display()))?;
    let snapshot: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", snapshot_path.display()))?;
    let files_indexed = snapshot
        .get("filesIndexed")
        .and_then(serde_json::Value::as_u64);
    let total_files = snapshot
        .pointer("/fileIndex/totalFiles")
        .and_then(serde_json::Value::as_u64);
    let generated_slices = json_string_array(snapshot.get("generatedSlices"));
    let stale_slices = json_string_array(snapshot.get("staleSlices"));
    let languages = json_string_array(snapshot.pointer("/repoContext/languages"));
    let frameworks = json_string_array(snapshot.pointer("/repoContext/frameworks"));
    let target = snapshot
        .get("target")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let discovery = snapshot
        .get("discovery")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let status = format!(
        "snapshot present; {} indexed file(s). Next: context regen repo",
        files_indexed.or(total_files).unwrap_or(0)
    );

    Ok(ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: true,
        status,
        target,
        discovery,
        files_indexed,
        total_files,
        languages,
        frameworks,
        generated_slices,
        stale_slices,
    })
}

pub(crate) fn json_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn normalize_kb_module_id(raw_id: &str) -> String {
    match raw_id.trim().to_ascii_lowercase().as_str() {
        "tm" | "threat" | "threats" => "threat-model".to_string(),
        "carlini" | "threat-hunt" => "carlini-threat-hunt".to_string(),
        "xray" | "x_ray" => "x-ray".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn unknown_kb_module_message(module_id: &str) -> String {
    format!(
        "unknown KB module {module_id:?}. Supported KB modules: {}. Next: kb context",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    )
}
