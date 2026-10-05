use super::*;
use crate::ShellApp;
use kuzushi_core::{Finding, Severity, TriageOutcome, TriageVerdict, V2Config};
use serde_json::json;

fn hydrate_diff(app: &mut ShellApp, left: &str, right: &str) {
    app.open_run_diff_for_test(left, right);
    app.hydrate_active_view_blocking();
}

#[test]
fn run_diff_hydrates_recorded_context_and_distinguishes_missing_from_omitted() {
    let temp = tempfile::tempdir().unwrap();
    write_run(temp.path(), "context-left", "a", json!([]));
    write_run(temp.path(), "context-right", "a", json!([]));
    let reference = json!({"modelId": format!("tm_{}", "a".repeat(32)),
        "revisionId": format!("tmr_{}", "b".repeat(32)), "sha256": format!("sha256:{}", "c".repeat(64))});
    let runs = temp.path().join(".kuzushi/v3/runs");
    std::fs::write(
        runs.join("context-left/scan-input.json"),
        json!({"threatModelRef": reference}).to_string(),
    )
    .unwrap();
    std::fs::write(
        runs.join("context-right/scan-input.json"),
        json!({"threatModelRef": null}).to_string(),
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    hydrate_diff(&mut app, "context-left", "context-right");
    let model = run_diff_model(&app, "context-left", "context-right");
    assert!(model
        .left_context
        .contains(reference["revisionId"].as_str().unwrap()));
    assert!(model
        .left_context
        .contains(reference["sha256"].as_str().unwrap()));
    assert_eq!(model.right_context, "explicitly no threat-model context");
    assert_eq!(
        run_diff_model(&app, "unrecorded", "unrecorded").context_status,
        "loading recorded contexts"
    );
    hydrate_diff(&mut app, "unrecorded", "unrecorded");
    assert_eq!(
        run_diff_model(&app, "unrecorded", "unrecorded").left_context,
        "not recorded or unreadable"
    );
}

#[test]
fn run_diff_model_compares_findings_by_stable_identity() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "abcdef123456",
        json!([
            finding_with_identity(
                "old-fp",
                "fi_shared",
                "shared",
                "high",
                "src/lib.rs",
                10,
                "semgrep"
            ),
            finding_with_review(
                "drift-old",
                "fi_changed",
                "changed item",
                "medium",
                "src/change.rs",
                15,
                "semgrep",
                "0.41",
                "needs_review"
            ),
            finding(
                "not-seen",
                "not seen item",
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
            finding_with_identity(
                "new-fp",
                "fi_shared",
                "shared",
                "high",
                "src/lib.rs",
                10,
                "semgrep"
            ),
            finding_with_review(
                "drift-new",
                "fi_changed",
                "changed item",
                "high",
                "src/change.rs",
                15,
                "semgrep",
                "0.91",
                "confirmed"
            ),
            finding("new", "new item", "critical", "src/new.rs", 30, "cpg")
        ]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    *app.findings_mut() = vec![
        reviewed_finding("fi_shared", TriageVerdict::TruePositive),
        reviewed_finding("fi_changed", TriageVerdict::FalsePositive),
    ];

    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");

    assert_eq!(model.left_revision, "rev:abcdef1");
    assert_eq!(model.right_revision, "rev:1234567");
    assert_eq!(model.left_status, "completed");
    assert_eq!(model.right_status, "completed");
    assert_eq!(model.unchanged_findings.len(), 1);
    assert_eq!(model.changed_findings.len(), 1);
    assert_eq!(model.changed_findings[0].title, "changed item");
    assert_eq!(model.changed_findings[0].before.severity, "medium");
    assert_eq!(model.changed_findings[0].after.severity, "high");
    assert_eq!(model.changed_findings[0].after.verdict, "confirmed");
    let decisions = model.decision_summary.as_ref().expect("decision summary");
    assert_eq!(decisions.identities, 2);
    assert_eq!(decisions.with_stored_decision, 2);
    assert_eq!(decisions.carry_forward, 1);
    assert_eq!(decisions.conflicts, 1);
    assert_eq!(model.new_findings.len(), 1);
    assert_eq!(model.new_findings[0].title, "new item");
    assert_eq!(model.new_findings[0].location, "src/new.rs:30");
    assert_eq!(model.not_seen.len(), 1);
    assert_eq!(model.not_seen[0].title, "not seen item");
    assert!(model.warnings.is_empty());
}

#[test]
fn run_diff_rejects_traversal_run_ids_without_reflecting_raw_paths() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    hydrate_diff(&mut app, "../../outside\nrun", "run-safe");
    let model = run_diff_model(&app, "../../outside\nrun", "run-safe");

    assert!(model
        .warnings
        .iter()
        .any(|warning| warning.contains("invalid run id")));
    assert!(model.new_findings.is_empty());
    assert!(model.not_seen.is_empty());
    assert!(model
        .warnings
        .iter()
        .all(|warning| !warning.contains("outside\nrun")));
}

#[test]
fn run_diff_model_separates_unique_uncertain_identity_matches() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "abcdef123456",
        json!([finding_with_rule(
            "old-line-fp",
            "demo.sql",
            "line shifted item",
            "medium",
            "src/db.rs",
            20,
            "semgrep"
        )]),
    );
    write_run(
        temp.path(),
        "run-right",
        "123456789abc",
        json!([finding_with_rule(
            "new-line-fp",
            "demo.sql",
            "line shifted item",
            "high",
            "src/db.rs",
            24,
            "semgrep"
        )]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");

    assert!(model.new_findings.is_empty());
    assert!(model.not_seen.is_empty());
    assert_eq!(model.uncertain_matches.len(), 1);
    let uncertain = &model.uncertain_matches[0];
    assert_eq!(uncertain.left_key, "old-line-fp");
    assert_eq!(uncertain.right_key, "new-line-fp");
    assert_eq!(uncertain.before.severity, "medium");
    assert_eq!(uncertain.after.severity, "high");
    assert_eq!(uncertain.left_location, "src/db.rs:20");
    assert_eq!(uncertain.right_location, "src/db.rs:24");
    assert!(uncertain
        .reason
        .contains("review before carrying decisions"));
}

#[test]
fn run_diff_model_does_not_carry_decisions_to_uncertain_matches() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "abcdef123456",
        json!([finding_with_identity_and_rule(
            "old-line-fp",
            "fi_reviewed_left",
            "demo.sql",
            "line shifted item",
            "medium",
            "src/db.rs",
            20,
            "semgrep"
        )]),
    );
    write_run(
        temp.path(),
        "run-right",
        "123456789abc",
        json!([finding_with_rule(
            "new-line-fp",
            "demo.sql",
            "line shifted item",
            "high",
            "src/db.rs",
            24,
            "semgrep"
        )]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    *app.findings_mut() = vec![reviewed_finding(
        "fi_reviewed_left",
        TriageVerdict::TruePositive,
    )];

    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");

    assert_eq!(model.uncertain_matches.len(), 1);
    let decisions = model.decision_summary.as_ref().expect("decision summary");
    assert_eq!(decisions.identities, 0);
    assert_eq!(decisions.with_stored_decision, 0);
    assert_eq!(decisions.carry_forward, 0);
    assert_eq!(decisions.conflicts, 0);
}

#[test]
fn run_diff_model_leaves_ambiguous_uncertain_matches_unpaired() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "abcdef123456",
        json!([
            finding_with_rule(
                "old-a",
                "demo.sql",
                "duplicate title",
                "medium",
                "src/db.rs",
                20,
                "semgrep"
            ),
            finding_with_rule(
                "old-b",
                "demo.sql",
                "duplicate title",
                "medium",
                "src/db.rs",
                30,
                "semgrep"
            )
        ]),
    );
    write_run(
        temp.path(),
        "run-right",
        "123456789abc",
        json!([finding_with_rule(
            "new-a",
            "demo.sql",
            "duplicate title",
            "medium",
            "src/db.rs",
            24,
            "semgrep"
        )]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");

    assert!(model.uncertain_matches.is_empty());
    assert_eq!(model.new_findings.len(), 1);
    assert_eq!(model.not_seen.len(), 2);
}

fn finding_with_identity(
    fingerprint: &str,
    identity_id: &str,
    title: &str,
    severity: &str,
    file_path: &str,
    line: u64,
    tool: &str,
) -> serde_json::Value {
    let mut value = finding(fingerprint, title, severity, file_path, line, tool);
    value["identityId"] = serde_json::Value::String(identity_id.to_string());
    value
}

fn finding_with_review(
    fingerprint: &str,
    identity_id: &str,
    title: &str,
    severity: &str,
    file_path: &str,
    line: u64,
    tool: &str,
    confidence: &str,
    verdict: &str,
) -> serde_json::Value {
    let mut value = finding_with_identity(
        fingerprint,
        identity_id,
        title,
        severity,
        file_path,
        line,
        tool,
    );
    value["triage"] = json!({
        "confidence": confidence,
        "verdict": verdict
    });
    value
}

fn reviewed_finding(identity_id: &str, verdict: TriageVerdict) -> Finding {
    let mut finding = Finding::new_semgrep(
        "demo.review",
        "src/app.ts",
        12,
        Some(12),
        Severity::High,
        "reviewed finding",
    );
    finding.identity_id = Some(identity_id.to_string());
    finding.triage = Some(TriageOutcome {
        verdict,
        confidence: 0.95,
        rationale: "loaded workspace review".to_string(),
        ..Default::default()
    });
    finding
}

#[test]
fn run_diff_model_warns_for_missing_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    hydrate_diff(&mut app, "missing-a", "missing-b");
    let model = run_diff_model(&app, "missing-a", "missing-b");

    assert_eq!(model.new_findings.len(), 0);
    assert_eq!(model.not_seen.len(), 0);
    assert_eq!(model.warnings.len(), 2);
    assert!(model.warnings[0].contains("missing-a"));
}

fn write_run(root: &std::path::Path, run_id: &str, sha: &str, findings: serde_json::Value) {
    write_run_with_status(root, run_id, sha, "completed", findings);
}

#[test]
fn run_diff_model_warns_when_comparison_run_is_partial_or_failed() {
    let temp = tempfile::tempdir().unwrap();
    write_run_with_status(
        temp.path(),
        "run-left",
        "abcdef123456",
        "partial",
        json!([finding(
            "left-only",
            "left only item",
            "high",
            "src/old.rs",
            20,
            "semgrep"
        )]),
    );
    write_run_with_status(
        temp.path(),
        "run-right",
        "123456789abc",
        "failed",
        json!([]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");

    assert_eq!(model.left_status, "partial");
    assert_eq!(model.right_status, "failed");
    assert_eq!(model.not_seen.len(), 1);
    assert!(model.warnings.iter().any(|warning| {
        warning.contains("run-left: run status partial") && warning.contains("incomplete coverage")
    }));
    assert!(model.warnings.iter().any(|warning| {
        warning.contains("run-right: run status failed") && warning.contains("incomplete coverage")
    }));
}

#[test]
fn run_diff_model_preserves_completed_status() {
    let temp = tempfile::tempdir().unwrap();
    write_run_with_status(
        temp.path(),
        "run-left",
        "abcdef123456",
        "completed",
        json!([]),
    );
    write_run_with_status(
        temp.path(),
        "run-right",
        "123456789abc",
        "completed",
        json!([]),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");

    assert_eq!(model.left_status, "completed");
    assert_eq!(model.right_status, "completed");
    assert!(model.warnings.is_empty(), "{:?}", model.warnings);
}

fn write_run_with_status(
    root: &std::path::Path,
    run_id: &str,
    sha: &str,
    status: &str,
    findings: serde_json::Value,
) {
    let run_dir = crate::ui_view_models::ui_run_dir(Some(root), run_id);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("run.json"),
        json!({
            "status": status,
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

fn finding_with_rule(
    fingerprint: &str,
    rule_id: &str,
    title: &str,
    severity: &str,
    file_path: &str,
    line: u64,
    tool: &str,
) -> serde_json::Value {
    let mut value = finding(fingerprint, title, severity, file_path, line, tool);
    value["ruleId"] = serde_json::Value::String(rule_id.to_string());
    value
}

fn finding_with_identity_and_rule(
    fingerprint: &str,
    identity_id: &str,
    rule_id: &str,
    title: &str,
    severity: &str,
    file_path: &str,
    line: u64,
    tool: &str,
) -> serde_json::Value {
    let mut value = finding_with_rule(fingerprint, rule_id, title, severity, file_path, line, tool);
    value["identityId"] = serde_json::Value::String(identity_id.to_string());
    value
}

#[test]
fn run_diff_distinguishes_reassessed_agentic_absence_from_uncovered_files() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "same-sha",
        json!([
            finding("inside", "inside", "high", "src/a.rs", 1, "agentic-sast"),
            finding(
                "outside",
                "outside",
                "high",
                "other/a.rs",
                1,
                "agentic-sast"
            )
        ]),
    );
    write_run(temp.path(), "run-right", "same-sha", json!([]));
    write_scan_receipt(temp.path(), "run-right");
    for (run, hash) in [("run-left", "a".repeat(64)), ("run-right", "b".repeat(64))] {
        let path = crate::ui_view_models::ui_run_dir(Some(temp.path()), run).join("result.json");
        std::fs::write(path, json!({"data":{"treeHash":hash}}).to_string()).unwrap();
    }
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");
    assert_eq!(model.left_revision, model.right_revision);
    assert_ne!(model.left_source, model.right_source);
    assert!(model.left_source.contains(&"a".repeat(64)));
    let inside = model
        .not_seen
        .iter()
        .find(|row| row.key == "inside")
        .unwrap();
    assert!(inside.reassessment_block.is_none());
    let outside = model
        .not_seen
        .iter()
        .find(|row| row.key == "outside")
        .unwrap();
    assert!(outside
        .reassessment_block
        .as_ref()
        .unwrap()
        .contains("outside"));
}

fn write_scan_receipt(root: &std::path::Path, run: &str) {
    let receipt = json!({
        "phase":"scan", "outcome":"completed", "runRefs":[run], "scan": {
            "scope":{"target":root.to_str().unwrap(), "paths":["src"]},
            "plan":{"selection":"explicit", "engines":["agentic-sast"]},
            "engines":[{"engine":"agentic-sast", "outcome":"complete"}],
            "findingDelta":{"added":0,"updated":0}, "durationMs":1,
            "targetSnapshot":{"target":root.to_str().unwrap(),"revision":"same-sha","dirty":true}
        }
    });
    let path = crate::ui_view_models::ui_run_dir(Some(root), run).join("phase-stages.jsonl");
    std::fs::write(path, format!("{receipt}\n")).unwrap();
}

#[test]
fn run_diff_never_infers_absence_from_a_missing_findings_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "run-left",
        "a",
        json!([finding(
            "inside",
            "inside",
            "high",
            "src/a.rs",
            1,
            "agentic-sast"
        )]),
    );
    write_run(temp.path(), "run-right", "b", json!([]));
    write_scan_receipt(temp.path(), "run-right");
    let path =
        crate::ui_view_models::ui_run_dir(Some(temp.path()), "run-right").join("findings.json");
    std::fs::remove_file(path).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    hydrate_diff(&mut app, "run-left", "run-right");
    let model = run_diff_model(&app, "run-left", "run-right");
    assert!(model.not_seen[0]
        .reassessment_block
        .as_ref()
        .unwrap()
        .contains("snapshot"));
}
