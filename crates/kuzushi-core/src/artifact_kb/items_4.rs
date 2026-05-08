use super::prelude::*;
use super::*;

pub(crate) fn discover_workspace_artifact_records(
    workspace: &WorkspaceTarget,
) -> Result<Vec<ArtifactKnowledgeRecord>> {
    let mut candidates = vec![
        ".kuzushi/context-snapshot.json".to_string(),
        ".kuzushi/threat-model.json".to_string(),
        ".kuzushi/tm-artifacts/normalized-threat-model.json".to_string(),
        "x-ray/x-ray.md".to_string(),
        "x-ray/entry-points.md".to_string(),
        "x-ray/invariants.md".to_string(),
        "x-ray/architecture.svg".to_string(),
    ];
    collect_run_artifact_paths(
        workspace.root(),
        &workspace.root().join(".kuzushi").join("runs"),
        &mut candidates,
    )?;
    candidates.sort();
    candidates.dedup();

    let mut records = Vec::new();
    for source_path in candidates {
        let absolute = workspace.root().join(&source_path);
        if !absolute.is_file() || !is_indexable_text_path(&absolute) {
            continue;
        }
        let metadata = json!({
            "sourceKind": if source_path.starts_with(".kuzushi/runs/") { "run-artifact" } else { "artifact-file" },
            "relativePath": source_path,
        });
        let module_id = infer_module_id(&source_path, &absolute)?;
        let run_id = infer_run_id(&source_path);
        let title = infer_title(&source_path, &absolute);
        if let Ok(record) = ArtifactKnowledgeRecord::from_text_source(
            workspace,
            source_path,
            module_id,
            run_id,
            title,
            Vec::new(),
            metadata,
        ) {
            records.push(record);
        }
    }
    Ok(records)
}

pub(crate) fn collect_run_artifact_paths(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_run_artifact_paths(root, &path, out)?;
        } else if path.is_file() && is_indexable_text_path(&path) {
            out.push(relative_workspace_path(root, &path));
        }
    }
    Ok(())
}

pub(crate) fn is_indexable_text_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("json" | "jsonl" | "md" | "txt" | "svg" | "sarif")
    )
}

pub(crate) fn infer_module_id(source_path: &str, absolute: &Path) -> Result<String> {
    if source_path == ".kuzushi/context-snapshot.json" {
        return Ok("context".to_string());
    }
    if source_path.starts_with("x-ray/") {
        return Ok("x-ray".to_string());
    }
    if source_path.contains("threat-model")
        || source_path.contains("randori")
        || source_path.contains("pasta-")
    {
        return Ok("threat-model".to_string());
    }
    if source_path.ends_with("summary.json") {
        let body = fs::read_to_string(absolute).unwrap_or_default();
        if body.contains("carliniThreatHunt") || body.contains("carlini-threat-hunt") {
            return Ok("carlini-threat-hunt".to_string());
        }
        if body.contains("xRay") || body.contains("x-ray") {
            return Ok("x-ray".to_string());
        }
        return Ok("sast".to_string());
    }
    Ok("artifact".to_string())
}

pub(crate) fn infer_run_id(source_path: &str) -> Option<String> {
    let parts = source_path.split('/').collect::<Vec<_>>();
    parts
        .windows(3)
        .find(|window| window[0] == ".kuzushi" && window[1] == "runs")
        .map(|window| window[2].to_string())
}
