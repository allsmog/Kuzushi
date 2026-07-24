use super::*;
use std::fs;

pub(super) fn seed_files(target: &Path) -> Result<(), String> {
    seed_project_files(target)?;
    seed_threat_model(target)?;
    seed_replay_trace(target)?;
    seed_scan_receipt(target)?;
    seed_attack_surface(target)
}

fn seed_scan_receipt(target: &Path) -> Result<(), String> {
    let mut summary = kuzushi_core::RunSummary::running(
        "scan-phase-run",
        "scan",
        Some("sast:scan".to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(Some(6))
    .with_cost(Some(0.042));
    summary.completed_at_unix = Some(summary.started_at_unix + 12);
    kuzushi_core::write_run_summary(target, &summary)
        .map(|_| ())
        .map_err(|error| format!("write scan run fixture: {error}"))
}

fn seed_attack_surface(target: &Path) -> Result<(), String> {
    let run_id = "map-phase-run";
    let mut summary = kuzushi_core::RunSummary::running(
        run_id,
        "repository-inventory:build",
        None,
        target.display().to_string(),
    )
    .complete();
    // The Scan and Map receipts are seeded within one clock tick. Keep the
    // artifact-owning Map receipt deterministically newest so the ordinary
    // latest-run hydration path projects its attack-surface artifact.
    summary.started_at_unix = summary.started_at_unix.saturating_add(1);
    summary.completed_at_unix = summary
        .completed_at_unix
        .map(|completed| completed.saturating_add(1));
    kuzushi_core::write_run_summary(target, &summary)
        .map_err(|error| format!("write map run fixture: {error}"))?;
    let artifact = serde_json::json!({
        "summary": {
            "highRisk": 2,
            "maxRiskScore": 91,
            "byRiskTier": {"critical": 1, "high": 1}
        },
        "surfaces": [
            {
                "title": "POST /login",
                "framework": "Axum",
                "risk": {"tier": "critical", "score": 91}
            },
            {
                "title": "GET /orders/:id",
                "framework": "Axum",
                "risk": {"tier": "high", "score": 72}
            }
        ]
    });
    let path = kuzushi_core::run_dir(target, run_id).join("attack-surface.json");
    let body = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| format!("serialize attack-surface fixture: {error}"))?;
    fs::write(&path, body).map_err(|error| io_error("write", &path, error))
}

// The reference finding sits at src/auth/login.rs:17, so the seeded file
// keeps a real sink on that exact line — the Review detail pane's SOURCE
// snippet in the canonical snapshots renders live code, not a drift note.
const LOGIN_FIXTURE_SOURCE: &str = r#"use crate::db::query;
use crate::http::{Request, Response};

pub struct LoginAttempt {
    pub username: String,
    pub password: String,
}

pub fn parse(request: &Request) -> LoginAttempt {
    LoginAttempt {
        username: request.form("username"),
        password: request.form("password"),
    }
}

pub fn login(attempt: &LoginAttempt) -> Response {
    let rows = query(&format!("SELECT * FROM users WHERE name = '{}'", attempt.username));
    match rows.first() {
        Some(user) => Response::session_for(user),
        None => Response::unauthorized(),
    }
}
"#;

fn seed_project_files(target: &Path) -> Result<(), String> {
    let files = [
        ("src/auth/login.rs", LOGIN_FIXTURE_SOURCE),
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
    let writer = kuzushi_core::run_lifecycle::RunItemWriter::open(target, "verify-phase-run", None)
        .map_err(|error| format!("open lifecycle fixture: {error}"))?;
    writer
        .emit_and_flush(kuzushi_core::run_lifecycle::RunItemRecord::new(
            kuzushi_core::run_lifecycle::RunItemId::new(),
            kuzushi_core::run_lifecycle::RunItemSource::Workflow,
            kuzushi_core::run_lifecycle::RunItemV1::DiagnosticNotice {
                level: kuzushi_core::run_lifecycle::DiagnosticLevel::Info,
                message: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                    "Payload reproduced",
                ),
            },
        ))
        .map(|_| ())
        .map_err(|error| format!("write lifecycle fixture: {error}"))
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> String {
    format!("{action} {}: {error}", path.display())
}
