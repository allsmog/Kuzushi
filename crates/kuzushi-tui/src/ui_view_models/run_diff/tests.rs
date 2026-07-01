use super::*;
use crate::ShellApp;
use kuzushi_core::V2Config;
use serde_json::json;

#[test]
fn run_diff_model_compares_findings_by_stable_identity() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "abcdef123456",
        json!([
            finding("same", "shared", "high", "src/lib.rs", 10, "semgrep"),
            finding(
                "removed",
                "removed item",
                "medium",
                "src/old.rs",
                20,
                "codeql"
            )
        ]),
    );
    write_run(
        temp.path(),
        "run-right",
        "123456789abc",
        json!([
            finding("same", "shared", "high", "src/lib.rs", 10, "semgrep"),
            finding("added", "added item", "critical", "src/new.rs", 30, "joern")
        ]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_diff_model(&app, "run-left", "run-right");

    assert_eq!(model.left_revision, "rev:abcdef1");
    assert_eq!(model.right_revision, "rev:1234567");
    assert_eq!(model.unchanged_count, 1);
    assert_eq!(model.added.len(), 1);
    assert_eq!(model.added[0].title, "added item");
    assert_eq!(model.added[0].location, "src/new.rs:30");
    assert_eq!(model.removed.len(), 1);
    assert_eq!(model.removed[0].title, "removed item");
    assert!(model.warnings.is_empty());
}

#[test]
fn run_diff_model_warns_for_missing_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_diff_model(&app, "missing-a", "missing-b");

    assert_eq!(model.added.len(), 0);
    assert_eq!(model.removed.len(), 0);
    assert_eq!(model.warnings.len(), 2);
    assert!(model.warnings[0].contains("missing-a"));
}

fn write_run(root: &std::path::Path, run_id: &str, sha: &str, findings: serde_json::Value) {
    let run_dir = crate::ui_view_models::ui_run_dir(Some(root), run_id);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("run.json"),
        json!({
            "status": "completed",
            "targetGit": {"sha": sha, "branch": "main", "dirty": false},
            "target": root.display().to_string()
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(run_dir.join("findings.json"), findings.to_string()).unwrap();
}

fn finding(
    fingerprint: &str,
    title: &str,
    severity: &str,
    file_path: &str,
    line: u64,
    tool: &str,
) -> serde_json::Value {
    json!({
        "fingerprint": fingerprint,
        "title": title,
        "severity": severity,
        "filePath": file_path,
        "startLine": line,
        "tool": tool
    })
}
