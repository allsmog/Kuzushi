use super::*;
use std::fs;

pub(super) fn seed_files(target: &Path) -> Result<(), String> {
    seed_project_files(target)?;
    seed_threat_model(target)?;
    seed_replay_trace(target)
}

fn seed_project_files(target: &Path) -> Result<(), String> {
    let files = [
        (
            "src/auth/login.rs",
            "pub fn login(input: &str) { query(input); }\n",
        ),
        (
            "src/api/orders.rs",
            "pub fn order(id: &str) { lookup(id); }\n",
        ),
        (
            "src/web/template.rs",
            "pub fn render(raw: &str) { html(raw); }\n",
        ),
    ];
    files
        .into_iter()
        .try_for_each(|(path, contents)| write_project_file(target, path, contents))
}

fn write_project_file(target: &Path, relative: &str, contents: &str) -> Result<(), String> {
    let path = target.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| format!("source fixture has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| io_error("create", parent, error))?;
    fs::write(&path, contents).map_err(|error| io_error("write", &path, error))
}

pub(super) fn seed_context(app: &mut ShellApp, target: &Path) -> Result<(), String> {
    let snapshot = kuzushi_core::context_snapshot_path(target);
    let parent = snapshot
        .parent()
        .ok_or_else(|| format!("context snapshot has no parent: {}", snapshot.display()))?;
    fs::create_dir_all(parent).map_err(|error| io_error("create", parent, error))?;
    fs::write(&snapshot, "{\"files\":3}\n").map_err(|error| io_error("write", &snapshot, error))?;
    app.domain_mut()
        .set_context_view(context_view(snapshot, target));
    Ok(())
}

fn context_view(snapshot: PathBuf, target: &Path) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path: Some(snapshot),
        exists: true,
        status: "snapshot present; 3 indexed files".to_string(),
        target: Some(target.display().to_string()),
        discovery: Some("bounded roots".to_string()),
        files_indexed: Some(3),
        total_files: Some(3),
        languages: vec!["Rust".to_string()],
        frameworks: vec!["Axum".to_string()],
        generated_slices: vec!["repo".to_string(), "routes".to_string()],
        stale_slices: Vec::new(),
    }
}

fn seed_threat_model(target: &Path) -> Result<(), String> {
    let document = serde_json::json!({
        "version": "2.0",
        "dfd": {
            "nodes": [
                {"id":"client", "type":"external-entity", "name":"Client", "trustZone":"external"},
                {"id":"api", "type":"process", "name":"API", "trustZone":"application"},
                {"id":"db", "type":"data-store", "name":"Orders DB", "trustZone":"data"}
            ],
            "flows": [
                {"id":"f1", "sourceId":"client", "targetId":"api", "description":"HTTPS request", "trustBoundaryIds":["edge"]},
                {"id":"f2", "sourceId":"api", "targetId":"db", "description":"SQL query", "trustBoundaryIds":["data-boundary"]}
            ],
            "trustBoundaries": [
                {"id":"edge", "name":"edge", "innerZone":"application", "outerZone":"external", "crossingFlowIds":["f1"]},
                {"id":"data-boundary", "name":"data", "innerZone":"data", "outerZone":"application", "crossingFlowIds":["f2"]}
            ]
        },
        "threats": []
    });
    kuzushi_core::capabilities::save_persistent_threat_model(target, &document, true)
        .map(|_| ())
        .map_err(|error| format!("write threat-model fixture: {error}"))
}

fn seed_replay_trace(target: &Path) -> Result<(), String> {
    let run_dir = kuzushi_core::run_dir(target, "verify-phase-run");
    fs::create_dir_all(&run_dir).map_err(|error| io_error("create", &run_dir, error))?;
    let trace = run_dir.join("trace.jsonl");
    fs::write(
        &trace,
        "{\"n\":1,\"kind\":\"proof\",\"label\":\"payload reproduced\"}\n",
    )
    .map_err(|error| io_error("write", &trace, error))
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> String {
    format!("{action} {}: {error}", path.display())
}
