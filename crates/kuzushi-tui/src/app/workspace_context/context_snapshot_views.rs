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
    match context_snapshot_path_state(&snapshot_path) {
        ContextSnapshotPathState::Missing => {
            return Ok(default_context_snapshot_view(Some(snapshot_path)));
        }
        ContextSnapshotPathState::NonFile => {
            return Ok(invalid_context_snapshot_view(snapshot_path, "not a file"));
        }
        ContextSnapshotPathState::Unreadable => {
            return Ok(malformed_context_snapshot_view(snapshot_path));
        }
        ContextSnapshotPathState::File => {}
    }

    match read_context_snapshot_json(&snapshot_path) {
        ContextSnapshotRead::Present(snapshot) => {
            Ok(present_context_snapshot_view(snapshot_path, &snapshot))
        }
        ContextSnapshotRead::Malformed => Ok(malformed_context_snapshot_view(snapshot_path)),
    }
}

fn context_snapshot_path_state(snapshot_path: &std::path::Path) -> ContextSnapshotPathState {
    match fs::metadata(snapshot_path) {
        Ok(metadata) if metadata.is_file() => ContextSnapshotPathState::File,
        Ok(_) => ContextSnapshotPathState::NonFile,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ContextSnapshotPathState::Missing
        }
        Err(_) => ContextSnapshotPathState::Unreadable,
    }
}

enum ContextSnapshotPathState {
    File,
    Missing,
    NonFile,
    Unreadable,
}

fn present_context_snapshot_view(
    snapshot_path: PathBuf,
    snapshot: &serde_json::Value,
) -> ContextSnapshotView {
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
    let status = context_snapshot_status(files_indexed, total_files);

    ContextSnapshotView {
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
    }
}

fn read_context_snapshot_json(snapshot_path: &std::path::Path) -> ContextSnapshotRead {
    let Ok(body) = fs::read_to_string(snapshot_path) else {
        return ContextSnapshotRead::Malformed;
    };

    match serde_json::from_str(&body) {
        Ok(value) => ContextSnapshotRead::Present(value),
        Err(_) => ContextSnapshotRead::Malformed,
    }
}

enum ContextSnapshotRead {
    Present(serde_json::Value),
    Malformed,
}

fn malformed_context_snapshot_view(snapshot_path: PathBuf) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: false,
        status: "malformed context snapshot. Next: context build".to_string(),
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

fn invalid_context_snapshot_view(snapshot_path: PathBuf, reason: &str) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: false,
        status: format!("malformed context snapshot ({reason}). Next: context build"),
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

fn context_snapshot_status(files_indexed: Option<u64>, total_files: Option<u64>) -> String {
    format!(
        "snapshot present; {} indexed file(s). Next: context regen repo",
        files_indexed.or(total_files).unwrap_or(0)
    )
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
        "carlini" | "threat-hunt" | "carlini-threat-hunt" => "offense-review".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_context_snapshot_view_surfaces_malformed_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(temp.path());
        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        fs::write(&snapshot_path, "{not-json").unwrap();

        let view = load_context_snapshot_view(snapshot_path.clone()).unwrap();

        assert_eq!(view.snapshot_path, Some(snapshot_path));
        assert!(!view.exists);
        assert_eq!(
            view.status,
            "malformed context snapshot. Next: context build"
        );
        assert!(view.languages.is_empty());
        assert!(view.frameworks.is_empty());
    }

    #[test]
    fn load_context_snapshot_view_surfaces_non_file_snapshot_path() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_path = kuzushi_core::context_snapshot_path(temp.path());
        fs::create_dir_all(&snapshot_path).unwrap();

        let view = load_context_snapshot_view(snapshot_path.clone()).unwrap();

        assert_eq!(view.snapshot_path, Some(snapshot_path));
        assert!(!view.exists);
        assert_eq!(
            view.status,
            "malformed context snapshot (not a file). Next: context build"
        );
        assert!(view.languages.is_empty());
        assert!(view.frameworks.is_empty());
    }
}
