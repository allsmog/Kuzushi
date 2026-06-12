use super::*;

use super::approval::{confirm_gate_for_tool, parse_pending_patch, ConfirmKind};
use super::artifacts::{
    append_run_status_event, append_trace_step, write_run_failure_handoff, write_run_summary,
};
use super::command_router::unknown_command_message;
use super::findings::{
    format_alias_table, format_chain_alias, parse_chain_alias, sorted_chain_aliases,
};
use super::settings::{auth_login_process_provider_arg, auth_login_status_message};
use super::state_transitions::{HotkeyTrigger, ViewHotkeyAction};
use super::view_state::ChainSeverity;
use crate::commands::{
    parse_command, ContextCommand, SastTaskCommand, SastTaskModeCommand, ShellCommand,
    WorkspaceCommand,
};
use crate::ui_view_models::ui_run_artifact_relative_path;
use kuzushi_core::run_artifacts::load_run_failures;
use kuzushi_core::{
    load_persistent_threat_model, load_run_summary, run_dir, save_persistent_threat_model,
    AttachmentRecord, FindingStore, OptionScope, OptionTarget, RuntimeConfig, RuntimeKind,
    Severity, ToolOptionStore, TriageOutcome, TriageVerdict,
};
use std::fs;

#[test]
fn mouse_capture_requires_truthy_opt_in() {
    assert!(!mouse_capture_setting_enabled(None));
    assert!(!mouse_capture_setting_enabled(Some("")));
    assert!(!mouse_capture_setting_enabled(Some("0")));
    assert!(!mouse_capture_setting_enabled(Some("false")));
    assert!(mouse_capture_setting_enabled(Some("1")));
    assert!(mouse_capture_setting_enabled(Some("true")));
    assert!(mouse_capture_setting_enabled(Some("YES")));
    assert!(mouse_capture_setting_enabled(Some(" on ")));
}

fn drain_tool(app: &mut ShellApp) {
    app.drain_next_tool_event_for_test(Duration::from_secs(15))
        .unwrap();
}

/// Drive a prerequisite chain to completion: while a chain is active,
/// drain background tool events and auto-reuse any pending reuse-or-
/// regenerate prompts.  Used by tests that exercise tools whose chain
/// includes deterministic prereqs (e.g. carlini → context:build →
/// threat-model:build).
#[allow(dead_code)]
fn drain_chain_with_auto_reuse(app: &mut ShellApp) {
    loop {
        if app.pending_prereq_prompt.is_some() {
            app.resolve_prereq_prompt(true);
            continue;
        }
        if app.tool_running.is_none() && app.pending_chain.is_none() {
            return;
        }
        app.drain_next_tool_event_for_test(Duration::from_secs(15))
            .unwrap();
    }
}

#[test]
fn missing_model_backed_prereqs_block_without_auto_accept_or_model_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/app.ts"), "res.send(req.query.name)\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.config.model = None;

    app.handle_command(ShellCommand::Use("offense-review".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"maxActors":1,"runsPerActor":1}"#.to_string()),
    });

    let plan = app.pending_prereq_prompt.as_ref().unwrap();
    assert_eq!(app.tool_running.as_deref(), None);
    assert_eq!(app.config.model, None);
    assert_eq!(plan.final_tool, "offense-review:threat-hunt");
    assert!(plan.steps.iter().any(|step| step.model_backed
        && step.artifact_state == PrereqArtifactState::Missing
        && step.cost_hint.contains("token cost unknown")));
    assert!(app.log.iter().any(|line| {
        line.prefix == "system" && line.body.contains("review approve/reuse/regenerate/cancel")
    }));
    assert!(!app
        .log
        .iter()
        .any(|line| line.body.contains("running automatically")));
}

#[test]
fn taint_iris_next_run_dot_uses_split_public_default_tool() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::Use("taint-iris-next".to_string()));

    assert_eq!(
        app.default_tool_for_focused_module().as_deref(),
        Some("taint-iris-next:dataflow-plan")
    );
    assert!(app.registry.resolve_tool("taint-iris-next:hunt").is_some());
    assert!(!app
        .registry
        .tools()
        .any(|tool| tool.name == "taint-iris-next:hunt"));
}

#[test]
fn prereq_plan_cancel_aborts_chain_before_dispatch() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.start_prereq_chain(
        prereq_steps_for("threat-model:build", tmp.path()),
        "threat-model:build".to_string(),
        serde_json::json!({}),
        workspace,
        None,
    );
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()));

    assert!(app.pending_chain.is_none());
    assert!(app.pending_prereq_prompt.is_none());
    assert_eq!(app.tool_running.as_deref(), None);
    assert!(app.log.iter().any(|line| {
        line.prefix == "system" && line.body.contains("prerequisite plan cancelled")
    }));
}

#[test]
fn cached_prereq_reuse_skips_prereq_and_dispatches_final_tool() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(kuzushi_core::workspace_state_root(tmp.path())).unwrap();
    fs::write(kuzushi_core::context_snapshot_path(tmp.path()), "{}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.start_prereq_chain(
        prereq_steps_for("threat-model:build", tmp.path()),
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        None,
    );
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()));

    assert_eq!(app.tool_running.as_deref(), Some("findings:list"));
    assert!(app.pending_prereq_prompt.is_none());
    assert!(app.log.iter().any(|line| {
        line.prefix == "system" && line.body.contains("reusing cached context snapshot")
    }));
    drain_tool(&mut app);
}

#[test]
fn cached_prereq_regenerate_runs_prereq_after_approval() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(kuzushi_core::workspace_state_root(tmp.path())).unwrap();
    fs::write(kuzushi_core::context_snapshot_path(tmp.path()), "{}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.start_prereq_chain(
        prereq_steps_for("threat-model:build", tmp.path()),
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        None,
    );
    app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()));

    assert_eq!(app.tool_running.as_deref(), Some("context:build"));
    assert!(app.pending_prereq_prompt.is_none());
    assert!(app.log.iter().any(|line| {
        line.prefix == "system" && line.body.contains("running after prerequisite approval")
    }));
    drain_tool(&mut app);
    if app.tool_running.is_some() {
        drain_tool(&mut app);
    }
}

#[test]
fn trusted_workflow_auto_accept_explicitly_starts_missing_prereq() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.trusted_workflow_auto_accept = true;

    app.start_prereq_chain(
        prereq_steps_for("threat-model:build", tmp.path()),
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        None,
    );

    assert_eq!(app.tool_running.as_deref(), Some("context:build"));
    assert!(app.pending_prereq_prompt.is_none());
    assert!(app.log.iter().any(|line| {
        line.prefix == "system" && line.body.contains("trusted workflow auto-accepted")
    }));
    drain_tool(&mut app);
    if app.tool_running.is_some() {
        drain_tool(&mut app);
    }
}

#[test]
fn live_activity_phase_labels_cover_long_running_states() {
    let phases = [
        LiveActivityPhase::Thinking,
        LiveActivityPhase::Reading,
        LiveActivityPhase::Searching,
        LiveActivityPhase::RunningTool,
        LiveActivityPhase::WritingArtifact,
        LiveActivityPhase::Waiting,
        LiveActivityPhase::Paused,
        LiveActivityPhase::Refused,
        LiveActivityPhase::Completed,
    ];
    let labels = phases.iter().map(|phase| phase.label()).collect::<Vec<_>>();

    assert_eq!(
        labels,
        vec![
            "thinking",
            "reading",
            "searching",
            "running tool",
            "writing artifact",
            "waiting",
            "paused",
            "refused",
            "completed"
        ]
    );
}

#[test]
fn taint_iris_next_activity_phases_match_split_runtime_boundary() {
    assert_eq!(
        live_activity_for_tool("taint-iris-next:finding-review", "reviewing").phase,
        LiveActivityPhase::Thinking
    );
    assert_eq!(
        live_activity_for_tool("taint-iris-next:dataflow-plan", "planning").phase,
        LiveActivityPhase::RunningTool
    );
    assert_eq!(
        live_activity_for_tool("taint-iris-next:source-sink-trace", "tracing").phase,
        LiveActivityPhase::RunningTool
    );
}

#[test]
fn offense_review_threat_hunt_activity_is_model_backed() {
    assert_eq!(
        live_activity_for_tool("offense-review:threat-hunt", "hunting").phase,
        LiveActivityPhase::Thinking
    );
}

#[test]
fn background_tool_sets_structured_live_activity_and_transcript_line() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.start_background_tool(
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        tool_run_status("findings:list"),
        None,
    );

    let activity = app.live_activity.as_ref().unwrap();
    assert_eq!(activity.phase, LiveActivityPhase::Reading);
    assert_eq!(activity.subject, "findings:list");
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "activity" && line.body.contains("reading: findings:list") }));
    drain_tool(&mut app);
    assert!(app
        .live_activity
        .as_ref()
        .is_some_and(|activity| activity.phase == LiveActivityPhase::Completed));
}

#[test]
fn threat_dependent_run_waits_for_pending_threat_review_decision() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_pending_threat_patch(ThreatPatch {
        goal: "review trust boundary".to_string(),
        summary: "tighten trust boundary".to_string(),
        patch: serde_json::json!({"assumptions":["admin flow in scope"]}),
        unsupported: Vec::new(),
    });

    app.handle_command(ShellCommand::RunTool {
        tool: Some("carlini-threat-hunt:run".to_string()),
        input: Some(r#"{"maxActors":1}"#.to_string()),
    });

    assert_eq!(app.tool_running.as_deref(), None);
    assert!(app.pending_chain.is_none());
    assert!(matches!(
        app.shell_view,
        ShellView::Threat(ThreatView::Summary)
    ));
    assert!(app.log.iter().any(|line| {
        line.prefix == "threats" && line.body.contains("apply or reject the pending threat")
    }));
    assert!(app
        .live_activity
        .as_ref()
        .is_some_and(|activity| activity.phase == LiveActivityPhase::Waiting));
}

#[test]
fn offense_review_threat_hunt_waits_for_pending_threat_review_decision() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_pending_threat_patch(ThreatPatch {
        goal: "review trust boundary".to_string(),
        summary: "tighten trust boundary".to_string(),
        patch: serde_json::json!({"assumptions":["admin flow in scope"]}),
        unsupported: Vec::new(),
    });

    app.handle_command(ShellCommand::RunTool {
        tool: Some("offense-review:threat-hunt".to_string()),
        input: Some(r#"{"maxActors":1}"#.to_string()),
    });

    assert_eq!(app.tool_running.as_deref(), None);
    assert!(app.pending_chain.is_none());
    assert!(matches!(
        app.shell_view,
        ShellView::Threat(ThreatView::Summary)
    ));
}

#[cfg(unix)]
fn fake_semgrep_binary(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("semgrep-fixture.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
cat <<'JSON'
{
  "results": [
    {
      "check_id": "javascript.express.security.audit.xss",
      "path": "server.js",
      "start": { "line": 9 },
      "end": { "line": 11 },
      "extra": {
        "severity": "ERROR",
        "message": "Detected unescaped user input in HTML response"
      }
    }
  ]
}
JSON
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_codeql_binary(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("codeql-fixture.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  printf 'name: test\n' > "$3/codeql-database.yml"
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) out="${arg#--output=}" ;;
    esac
  done
  cat > "$out" <<'JSON'
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "js/sql-injection",
              "properties": { "problem": { "severity": "error" } }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "message": { "text": "User input reaches SQL sink" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "server.js" },
                "region": { "startLine": 9 }
              }
            }
          ]
        }
      ]
    }
  ]
}
JSON
  exit 0
fi
echo "unexpected codeql args: $*" >&2
exit 2
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_curl_binary(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("curl-fixture.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
cat <<'HTTP'
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express

<html><title>Acme</title></html>
HTTP
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_nmap_binary(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("nmap-fixture.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
cat <<'OUT'
Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/
OUT
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_triage_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("triage-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"verdict":"true_positive","confidence":0.91,"rationale":"mock shell bridge"}}
JSON
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_ask_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("ask-bridge.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"What should I run first?"*)
    cat <<'JSON'
{"ok":true,"text":"Run context build, then scan .","costUsd":0.034}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected ask request"}'
    exit 1
    ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_agentic_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("agentic-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"agentic/sql-injection","filePath":"src/db.ts","startLine":1,"severity":"ERROR","message":"User input reaches SQL query","confidence":"HIGH","evidence":"Source: req.query.q -> sink: db.query"}]}}
JSON
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_variant_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("variant-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"variant analysis agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"variants":[{"filePath":"src/other.ts","startLine":9,"severity":"ERROR","message":"exec with untrusted input","confidence":"HIGH","rationale":"same source reaches exec","cwe":["CWE-78"]}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected variant request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

fn seed_true_positive_finding(workspace: &WorkspaceTarget) -> String {
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-variant", workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "javascript.express.command-injection",
        "src/app.ts",
        1,
        None,
        Severity::High,
        "Command injection via child_process.exec",
    );
    let fingerprint = finding.fingerprint.clone();
    let finding_id = store.insert_finding("run-variant", &finding).unwrap();
    store
        .save_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.92,
                rationale: "request body reaches exec".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    store
        .complete_scan_run("run-variant", "completed", 1)
        .unwrap();
    fingerprint
}

#[cfg(unix)]
fn fake_ndiff_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("ndiff-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"N-day variant hunter"*)
    cat <<'JSON'
{"ok":true,"structured":{"variants":[{"filePath":"src/parser.c","startLine":7,"severity":"ERROR","message":"memcpy without bounds check","confidence":"HIGH","rationale":"length reaches memcpy","cwe":["CWE-787"]}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected ndiff request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_taint_iris_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("taint-iris-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Taint CWE selector"*)
    cat <<'JSON'
{"ok":true,"structured":{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"database query uses request input"}]}}
JSON
    ;;
  *"IRIS-style taint analysis"*)
    cat <<'JSON'
{"ok":true,"structured":{"findings":[{"title":"Request input reaches SQL query","cwe":"CWE-89","severity":"high","filePath":"src/db.ts","startLine":1,"message":"The request query is concatenated into a SQL query.","sourceSinkTrace":"req.query.q -> db.query","taintPath":[{"filePath":"src/db.ts","line":1,"message":"source and sink","snippet":"db.query(req.query.q)"}],"confidence":"high","exploitPreconditions":"attacker controls q"}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected taint-iris request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_taint_iris_next_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("taint-iris-next-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Taint IRIS Next agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"selectedCwes":[{"cwe":"CWE-89","reason":"raw query receives request data","catalogSignals":["sink: query("],"sourceSpec":"request query parameters","sinkSpec":"database query calls","sanitizerSpec":"parameterized query APIs","customCweRationale":""}],"findings":[{"title":"Request parameter reaches raw SQL query","cwe":"CWE-89","severity":"high","confidence":"medium","evidenceLevel":"linked","filePath":"src/routes.ts","startLine":1,"message":"The query uses request-controlled data in SQL construction.","sourceSinkTrace":"req.query.id -> db.query(sql)","catalogSignals":["source: req.query","sink: query("],"customCweRationale":"","taintPath":[{"filePath":"src/routes.ts","line":1,"message":"source and SQL sink","snippet":"db.query(req.query.id)"}]}],"triage":[{"status":"finding","cwe":"CWE-89","evidenceLevel":"linked","rationale":"request data reaches raw SQL query","filePath":"src/routes.ts","line":1,"catalogSignals":["sink: query("]}],"notes":[]}}
JSON
    ;;
  *"Taint IRIS Next catalog architect"*)
    cat <<'JSON'
{"ok":true,"structured":{"catalog":[{"cwe":"CWE-89","name":"SQL Injection","taintClass":"sql-injection","languages":["typescript"],"sourceSignals":["req.query"],"sinkSignals":["db.query"],"sanitizerSignals":["parameterized query"],"structuralQueries":["db.query"],"regexMarkers":[],"score":90,"reasons":["fixture route builds SQL from request input"]}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected taint-iris-next request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_carlini_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("carlini-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"carlini-threat-hunt/actor-xss","filePath":"src/app.ts","startLine":9,"severity":"ERROR","message":"Actor-controlled input reaches HTML response","confidence":"HIGH","evidence":"Source: request query -> sink: response HTML"}]}}
JSON
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_systems_hunt_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("systems-hunt-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Systems Hunt invariant extractor"*)
    cat <<'JSON'
{"ok":true,"structured":{"invariants":[{"id":"inv-1","surfaceId":"surface-1","kind":"length-buffer-coupling","summary":"packet length must fit the fixed buffer","statement":"length is checked before copy","rationale":"copy uses packet-controlled length","evidence":["memcpy"],"attackerControlledFields":["len"],"cheapVerifiable":true}]}}
JSON
    ;;
  *"Systems Hunt trigger synthesizer"*)
    cat <<'JSON'
{"ok":true,"structured":{"triggers":[{"id":"trig-1","surfaceId":"surface-1","orderedSteps":["send oversized packet"],"boundaryAssignments":{"len":"4096"},"statePreconditions":["connected"],"attackerControlledFields":["len"],"expectedPrimitive":"stack overwrite","cheapVerifiable":true,"rationale":"length reaches memcpy"}]}}
JSON
    ;;
  *"Systems Hunt low-level vulnerability hunter"*)
    cat <<'JSON'
{"ok":true,"structured":{"findings":[{"title":"Oversized packet length reaches fixed buffer","cwe":"CWE-787","severity":"ERROR","filePath":"src/parser.c","startLine":3,"message":"packet length is copied into a 64-byte stack buffer","reasoning":"len comes from the packet header","triggerHypothesisIds":["trig-1"],"violatedInvariantIds":["inv-1"],"triggerSequence":["send len=4096"],"attackerControlledFields":["len"],"memoryPrimitive":"stack overwrite","cheapVerifiable":true}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected systems-hunt request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

fn write_systems_hunt_fixture(dir: &PathBuf) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
            dir.join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
}

fn write_carlini_threat_model_fixture(dir: &PathBuf) {
    let threat_model_path = kuzushi_core::capabilities::persistent_threat_model_path(dir);
    fs::create_dir_all(threat_model_path.parent().unwrap()).unwrap();
    fs::write(
            threat_model_path,
            r#"{"version":"2.0","dfd":{"nodes":[{"id":"actor-user","type":"external-entity","name":"Authenticated User","description":"External authenticated user","trustZone":"external"},{"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}],"flows":[{"id":"flow-1","sourceId":"actor-user","targetId":"web","description":"profile request","trustBoundaryIds":["tb-1"],"protocol":"https"}],"trustBoundaries":[{"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}]},"threats":[{"id":"T-001","actorIds":["actor-user"],"flowIds":["flow-1"],"targetElementIds":["web"],"category":"tampering","title":"Profile HTML injection","description":"query reaches HTML","attackVector":"crafted profile query","impact":"high","likelihood":"medium","affectedFiles":[{"filePath":"src/app.ts","startLine":9}]}],"summary":{"total":1,"bySeverity":{"high":1},"byCategory":{"tampering":1}}}"#,
        )
        .unwrap();
}

#[cfg(unix)]
fn fake_verify_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("verify-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"fingerprint":"fp-from-bridge","exploitable":true,"poc_payload":"curl -X POST /admin","poc_description":"POST reaches admin sink","attack_vector":"curl POST /admin","preconditions":["network access"],"confidence":0.84,"proof_level":3,"proof_verdict":"exploited"}}
JSON
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_patch_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("patch-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"diff":"--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n","explanation":"sanitize query input"}}
JSON
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn init_git_repo(dir: &PathBuf) {
    for args in [
        vec!["init"],
        vec!["config", "user.email", "kuzushi@example.test"],
        vec!["config", "user.name", "Kuzushi Test"],
        // Stay hermetic against a host git config that forces signing.
        vec!["config", "commit.gpgsign", "false"],
        vec!["config", "tag.gpgsign", "false"],
        vec!["add", "."],
        vec!["commit", "-m", "fixture"],
    ] {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
fn fake_threat_model_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("threat-model-bridge.sh");
    fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"document":{"version":"2.0","dfd":{"nodes":[{"id":"actor-user","type":"external-entity","name":"User","description":"External user","trustZone":"external"},{"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}],"flows":[{"id":"flow-1","description":"request","sourceId":"actor-user","targetId":"web","trustBoundaryIds":["tb-1"]}],"trustBoundaries":[{"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}]},"threats":[{"id":"T-001","targetElementIds":["web"],"category":"spoofing","title":"Spoofed login","description":"stolen token","attackVector":"token theft","preconditions":[],"impact":"high","likelihood":"medium","existingMitigations":[],"missingMitigations":["bind sessions"],"relatedCwe":["CWE-287"],"affectedFiles":[{"filePath":"src/auth.ts","startLine":1}]}],"summary":{"total":1,"bySeverity":{"high":1},"byCategory":{"spoofing":1}}}}}
JSON
"#,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_x_ray_bridge(dir: &PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("x-ray-bridge.sh");
    fs::write(
            &binary,
            r##"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"xRayMarkdown":"# X-Ray\n\n## X-Ray Verdict\nWATCH\nReview invariants before launch.\n","entryPointsMarkdown":"# Entry Points\n\n> App | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n","invariantsMarkdown":"# Invariants\n\n### G-1 Balance conservation\n","architectureSvg":"<svg xmlns=\"http://www.w3.org/2000/svg\" />\n"}}
JSON
"##,
        )
        .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[test]
fn logs_command_routes_to_full_screen_transcript() {
    // M1 §1.1: `logs` (alias `log`, `transcript`) switches into the new
    // full-screen `ShellView::Logs` view so operators can scroll through
    // the entire 500-line buffer instead of seeing only the embedded strip.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(parse_command("logs"));
    assert!(matches!(app.shell_view, ShellView::Logs));

    // Aliases (log, transcript) reach the same view.
    app.shell_view = ShellView::Home;
    app.handle_command(parse_command("log"));
    assert!(matches!(app.shell_view, ShellView::Logs));

    app.shell_view = ShellView::Home;
    app.handle_command(parse_command("transcript"));
    assert!(matches!(app.shell_view, ShellView::Logs));
}

#[test]
fn logs_view_routes_j_k_and_page_keys_to_logs_scroll() {
    // M1 §1.1: while in the Logs view, j/k and PgDn/PgUp must drive the
    // dedicated `logs_scroll` field rather than the shared `scroll_offset`
    // — otherwise the transcript would visually stay pinned while the
    // generic offset advances.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Logs;
    app.scroll_offset = 0;
    app.logs_scroll = 0;

    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.logs_scroll, 10);
    assert_eq!(app.scroll_offset, 0);

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.logs_scroll, 11);

    app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()));
    assert_eq!(app.logs_scroll, 0);

    app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()));
    assert_eq!(app.logs_scroll, usize::MAX);
}

#[test]
fn help_command_routes_to_rust_shell_help_without_removed_cli_paths() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(parse_command("/help"));

    assert_eq!(app.shell_view, ShellView::Help);
    let help_log = app
        .log
        .iter()
        .filter(|line| line.prefix == "help")
        .map(|line| line.body.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help_log.contains("help"));
    assert!(help_log.contains("Examples"));
    assert!(!help_log.contains("--load"));
    assert!(!help_log.contains("Ink"));
    assert!(!help_log.contains("TypeScript"));
}

#[test]
fn completion_covers_commands_stateful_arguments_and_config_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-complete", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "dangerous sink",
    );
    store.insert_finding("run-complete", &finding).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.scan = Some(ScanPanelState {
        run_id: Some("run-active-123".to_string()),
        target: workspace.root().to_path_buf(),
        stage: "completed".to_string(),
        findings_count: 1,
        running: false,
        abort_requested: false,
        error: None,
    });
    app.kb_view.attachments = vec![AttachmentRecord {
        id: "A-123456789abc".to_string(),
        module_id: "context".to_string(),
        kind: kuzushi_core::AttachmentKind::Path,
        source: "README.md".to_string(),
        title: "README.md".to_string(),
        metadata_only: false,
        content_hash: Some("abc".to_string()),
        byte_count: Some(3),
        status: "indexed".to_string(),
        updated_at_unix: 1,
    }];

    for expected in ["/options", "/tasks", "/kb", "/context", "/auth"] {
        assert!(
            app.completion_candidates("/")
                .iter()
                .any(|candidate| candidate == expected),
            "missing slash completion {expected}"
        );
    }
    assert!(app.completion_candidates("m").contains(&"m".to_string()));
    assert!(app
        .completion_candidates("use sa")
        .contains(&"use sast".to_string()));
    assert!(app
        .completion_candidates("run sem")
        .contains(&"run semgrep:scan".to_string()));
    assert!(app
        .completion_candidates("set tri")
        .contains(&"set triage".to_string()));
    assert!(app
        .completion_candidates("task block co")
        .contains(&"task block codeql".to_string()));
    assert!(app
        .completion_candidates("open F-")
        .contains(&"open F-0001".to_string()));
    assert!(app
        .completion_candidates("replay run-")
        .contains(&"replay run-active-123".to_string()));
    assert!(app
        .completion_candidates("config runtime.")
        .contains(&"config runtime.kind".to_string()));
    assert!(app
        .completion_candidates("detach A-")
        .contains(&"detach A-123456789abc".to_string()));
}

#[test]
fn tab_key_applies_shell_and_argument_completion() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("/con");
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(app.input, "/context");

    app.set_input("task block co");
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(app.input, "task block codeql");
}

#[test]
fn command_reducer_updates_model_without_terminal() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Model(Some("openai:gpt-4.1".to_string())));

    assert_eq!(app.config.model.as_deref(), Some("openai:gpt-4.1"));
    assert!(app.log.iter().any(|line| line.prefix == "model"));
}

#[test]
fn command_reducer_focuses_existing_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Use("semgrep".to_string()));

    assert_eq!(app.focused_module.as_deref(), Some("semgrep"));
}

#[test]
fn findings_command_loads_store_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "dangerous sink",
    );
    store.insert_finding("run-1", &finding).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Findings);

    assert_eq!(app.findings.len(), 1);
    assert_eq!(app.shell_view, ShellView::Findings);
}

#[test]
fn open_command_accepts_deterministic_finding_alias() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "dangerous sink",
    );
    store.insert_finding("run-1", &finding).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Open("F-0001".to_string()));

    assert_eq!(app.shell_view, ShellView::Finding);
    assert_eq!(
        app.selected_finding
            .as_ref()
            .map(|finding| finding.fingerprint.as_str()),
        Some(finding.fingerprint.as_str())
    );
}

#[test]
fn open_command_resolves_alias_from_stable_sorted_mapping() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let mut stable_first = make_finding(Severity::High, "aaaa1111", "stable first");
    let stable_later = make_finding(Severity::High, "zzzz1111", "stored later");
    stable_first.file_path = "src/a.rs".to_string();
    store.insert_finding("run-1", &stable_first).unwrap();
    store.insert_finding("run-1", &stable_later).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Open("F-0001".to_string()));

    assert_eq!(app.shell_view, ShellView::Finding);
    assert_eq!(
        app.selected_finding
            .as_ref()
            .map(|finding| finding.fingerprint.as_str()),
        Some("aaaa1111")
    );
}

#[test]
fn scan_completion_logs_same_stable_alias_used_by_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let stable_first = make_finding(Severity::High, "aaaa1111", "stable first");
    let stored_later = make_finding(Severity::High, "zzzz1111", "stored later");
    store.insert_finding("run-1", &stable_first).unwrap();
    store.insert_finding("run-1", &stored_later).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.scan = Some(ScanPanelState {
        run_id: None,
        target: workspace.root().to_path_buf(),
        stage: "running scan".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.activity = Some(ActivitySession::new("scan-pending"));
    app.apply_scan_event(ScanEvent::Finished {
        run_id: "run-1".to_string(),
        findings_count: 2,
    });

    assert!(app.log.iter().any(|line| {
        line.prefix == "scan" && line.body.contains("top alias F-0001 -> aaaa1111")
    }));
    assert!(app.log.iter().any(
        |line| line.prefix == "result" && line.body == "fail (2 findings / 2 high) exit_hint=1"
    ));
    assert_eq!(
        kuzushi_core::stable_finding_alias(&app.findings, "aaaa1111").as_deref(),
        Some("F-0001")
    );
    assert_eq!(
        app.activity.as_ref().map(|session| session.run_id.as_str()),
        Some("run-1")
    );
    let events =
        fs::read_to_string(kuzushi_core::run_dir(workspace.root(), "run-1").join("events.jsonl"))
            .unwrap();
    assert!(events.contains(r#""status":"completed""#));
    assert!(events.contains(r#""tool":"sast:scan""#));
}

#[test]
fn run_command_dispatches_focused_module_tool_through_registry() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("dep-hygiene".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: None,
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(
        |line| line.prefix == "result" && line.body.contains("dep-hygiene: 1 risky specifier")
    ));
}

#[test]
fn run_command_dispatches_context_build_and_writes_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("context".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"sampleLimit":10}"#.to_string()),
    });

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.has_running_work());
    assert!(app.log.iter().any(|line| {
        line.prefix == "tool" && line.body.contains("running context:build in background")
    }));
    drain_tool(&mut app);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result" && line.body.contains("context:build indexed 2 files")
    }));
    assert!(app.context_view.exists);
    assert!(kuzushi_core::context_snapshot_path(workspace.root()).exists());
}

#[test]
fn run_dot_dispatches_focused_default_tool() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(parse_command("use context"));
    app.handle_command(parse_command(r#"run . {"sampleLimit":10}"#));

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.has_running_work());
    drain_tool(&mut app);
    assert!(app.context_view.exists);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result" && line.body.contains("context:build indexed 2 files")
    }));
}

#[test]
fn context_build_command_dispatches_context_build_and_writes_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::Context(ContextCommand::Build));

    // Auto-open lifts the user into the Activity view so the live trace
    // feed is visible while context:build runs. The original test
    // contract (shell_view == Context after dispatch) is now superseded.
    assert_eq!(app.shell_view, ShellView::Activity);
    assert_eq!(app.focused_module.as_deref(), Some("context"));
    assert!(app.has_running_work());
    drain_tool(&mut app);
    assert!(app.context_view.exists);
    assert!(
        app.log
            .iter()
            .any(|line| line.prefix == "result"
                && line.body.contains("context:build indexed 2 files"))
    );
    assert!(kuzushi_core::context_snapshot_path(workspace.root()).exists());
}

#[test]
fn context_status_displays_existing_snapshot_or_missing_state() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::Context(ContextCommand::Status));

    assert_eq!(app.shell_view, ShellView::Context);
    assert!(!app.context_view.exists);
    assert!(app.context_view.status.contains("missing"));

    app.handle_command(ShellCommand::Context(ContextCommand::Build));
    drain_tool(&mut app);
    app.handle_command(ShellCommand::Context(ContextCommand::Show));

    assert!(app.context_view.exists);
    assert!(app.context_view.status.contains("snapshot present"));
}

#[test]
fn context_regen_unknown_slice_is_actionable_and_does_not_mutate_state() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::Context(ContextCommand::Regen(
        "routes".to_string(),
    )));

    let error = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("unknown context slice"));
    assert!(error.contains("Next: context regen repo"));
    assert!(!kuzushi_core::context_snapshot_path(workspace.root()).exists());
}

#[test]
fn workspace_status_reports_no_active_workspace() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::Workspace(WorkspaceCommand::Status));

    assert_eq!(app.shell_view, ShellView::Workspace);
    assert_eq!(app.workspace_view.root, None);
    assert!(app.workspace_view.status.contains("no active workspace"));
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "workspace" && line.body.contains("start shell with --target")));
}

#[test]
fn workspace_export_findings_to_temp_path() {
    let tmp = tempfile::tempdir().unwrap();
    let export_dir = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/path",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "request data reaches sink",
            ),
        )
        .unwrap();
    let output = export_dir.path().join("findings.json");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
        output: output.clone(),
    }));

    assert_eq!(app.shell_view, ShellView::Workspace);
    assert_eq!(app.workspace_view.findings_count, Some(1));
    assert_eq!(
        app.workspace_view.last_export.as_deref(),
        Some(output.as_path())
    );
    let exported: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(exported["count"], serde_json::json!(1));
    assert_eq!(
        exported["findings"][0]["message"],
        "request data reaches sink"
    );
}

#[test]
fn workspace_export_rejects_unsupported_formats_actionably() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
        output: tmp.path().join("findings.xml"),
    }));

    let error = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("unsupported workspace findings export extension"));
    assert!(error.contains("Next: workspace export findings <path>.json"));
    assert!(!tmp.path().join("findings.xml").exists());
}

#[test]
fn run_command_applies_session_options_to_focused_module_tool() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(tmp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("context:build".to_string()),
        "sampleLimit",
        serde_json::json!(1),
    );
    app.handle_command(ShellCommand::Use("context".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: None,
    });
    drain_tool(&mut app);

    let snapshot =
        fs::read_to_string(kuzushi_core::context_snapshot_path(workspace.root())).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(
        snapshot["filesSample"].as_array().unwrap().len(),
        1,
        "stored sampleLimit should affect focused-module run"
    );
}

#[test]
fn explicit_run_input_overrides_stored_tool_options() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(tmp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("context:build".to_string()),
        "sampleLimit",
        serde_json::json!(1),
    );
    app.handle_command(ShellCommand::Use("context".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"sampleLimit":2}"#.to_string()),
    });
    drain_tool(&mut app);

    let snapshot =
        fs::read_to_string(kuzushi_core::context_snapshot_path(workspace.root())).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(
        snapshot["filesSample"].as_array().unwrap().len(),
        2,
        "explicit run input should beat stored options"
    );
}

#[test]
fn scan_path_reads_stored_sast_options() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "severity",
        serde_json::json!("critical,high"),
    );

    let input = app.scan_input_from_store().unwrap();

    assert_eq!(input["severity"], serde_json::json!(["critical", "high"]));
    assert_eq!(input.get("severity_filter"), None);
}

#[test]
fn scan_path_builds_canonical_sast_tool_input_from_option_store() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "disabled_tasks",
        serde_json::json!("semgrep,codeql"),
    );
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!("yes"),
    );

    let input = app.scan_input_from_store().unwrap();

    assert_eq!(
        input["disabledTasks"],
        serde_json::json!(["semgrep", "codeql"])
    );
    assert_eq!(input["triage"], serde_json::json!(true));
    assert_eq!(input["taskMode"], serde_json::json!("auto"));
    assert_eq!(input.get("disabled_tasks"), None);
}

#[test]
fn task_commands_update_sast_scan_selection_options() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::Tasks);
    assert_eq!(app.shell_view, ShellView::SastTasks);
    assert_eq!(app.focused_module.as_deref(), Some("sast"));

    app.handle_command(ShellCommand::Task(SastTaskCommand::Block(
        "semgrep".to_string(),
    )));
    let prepared = app
        .registry
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
        .unwrap();
    assert_eq!(prepared["disabledTasks"], serde_json::json!(["semgrep"]));

    assert_eq!(prepared["disabledTasks"], serde_json::json!(["semgrep"]));
    assert_eq!(prepared["taskMode"], serde_json::json!("auto"));
    assert_eq!(prepared.get("disabled_tasks"), None);
}

#[test]
fn task_mode_manual_seeds_and_allows_tasks_for_sast_scan() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::Task(SastTaskCommand::Mode(
        SastTaskModeCommand::Manual,
    )));
    app.handle_command(ShellCommand::Task(SastTaskCommand::Allow(
        "codeql".to_string(),
    )));

    let prepared = app
        .registry
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
        .unwrap();
    assert_eq!(prepared["taskMode"], serde_json::json!("manual"));
    assert!(prepared["tasks"]
        .as_array()
        .is_some_and(|tasks| tasks.iter().any(|task| task == "codeql")));
}

#[test]
fn unknown_task_id_lists_valid_ids_and_does_not_mutate_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Task(SastTaskCommand::Block(
        "semgrep".to_string(),
    )));
    let before = app.option_store.clone();

    app.handle_command(ShellCommand::Task(SastTaskCommand::Allow(
        "bogus-task".to_string(),
    )));

    assert_eq!(app.option_store, before);
    let error = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("unknown SAST task"));
    assert!(error.contains("semgrep"));
    assert!(error.contains("codeql"));
    assert!(error.contains("Next: /tasks"));
}

#[test]
fn ux_empty_and_error_states_name_next_real_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::Findings);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "findings" && line.body.contains("Next: scan") }));

    let mut no_workspace_app = ShellApp::new(V2Config::default(), None);
    no_workspace_app.handle_command(ShellCommand::Workspace(WorkspaceCommand::Status));
    assert!(no_workspace_app
        .log
        .iter()
        .any(|line| { line.prefix == "workspace" && line.body.contains("Next: scan <target>") }));

    app.handle_command(ShellCommand::Use("sat".to_string()));
    let unknown_module = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(unknown_module.contains("unknown module"));
    assert!(unknown_module.contains("Closest: sast"));
    assert!(unknown_module.contains("Next: modules or use <module-id>"));

    app.handle_command(ShellCommand::Use("recon".to_string()));
    assert_ne!(app.focused_module.as_deref(), Some("recon"));
    assert!(app
        .log
        .iter()
        .rev()
        .any(|line| { line.prefix == "error" && line.body.contains("unknown module \"recon\"") }));

    app.handle_command(ShellCommand::RunTool {
        tool: Some("missing:tool".to_string()),
        input: None,
    });
    let unknown_tool = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(unknown_tool.contains("unknown tool"));
    assert!(unknown_tool.contains("Next:"));
    assert!(unknown_tool.contains("tools"));

    let before = app.option_store.clone();
    app.handle_command(ShellCommand::Task(SastTaskCommand::Allow(
        "not-a-task".to_string(),
    )));
    assert_eq!(app.option_store, before);
    let unknown_task = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(unknown_task.contains("Valid task IDs"));
    assert!(unknown_task.contains("Next: /tasks"));

    app.scan = Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.apply_scan_event(ScanEvent::Failed {
        error: "semgrep: could not find scanner binary \"semgrep\"".to_string(),
    });
    let missing_scanner = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(missing_scanner.contains("could not find scanner binary"));
    assert!(missing_scanner.contains("Next:"));
    assert!(missing_scanner.contains("task block semgrep"));
    assert!(app.log.iter().any(|line| {
        line.prefix == "error"
            && line.body.contains("stage=scan task=sast:scan")
            && line.body.contains("could not find scanner binary")
    }));
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body == "fail (scan failed) exit_hint=1"));

    app.apply_scan_event(ScanEvent::Failed {
        error: "internal shell-state error: selected finding disappeared".to_string(),
    });
    let internal = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(internal.contains("internal shell-state error"));
    assert!(internal.contains("Next:"));
}

#[test]
fn kb_attach_detach_and_reparse_store_under_v2() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("notes.md"), "first\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("threat-model".to_string()));

    app.handle_command(ShellCommand::Attach("notes.md".to_string()));

    assert_eq!(app.shell_view, ShellView::KnowledgeBase);
    assert_eq!(app.kb_view.module_id, "threat-model");
    assert!(workspace
        .root()
        .join(".kuzushi/v2/attachments.json")
        .exists());
    let record = app
        .kb_view
        .attachments
        .iter()
        .find(|record| record.module_id == "threat-model")
        .cloned()
        .unwrap();
    assert_eq!(record.source, "notes.md");
    let first_hash = record.content_hash.clone();

    fs::write(tmp.path().join("notes.md"), "second\n").unwrap();
    app.handle_command(ShellCommand::Reparse(record.id.clone()));
    let reparsed = app
        .kb_view
        .attachments
        .iter()
        .find(|candidate| candidate.id == record.id)
        .unwrap();
    assert_ne!(first_hash, reparsed.content_hash);

    app.handle_command(ShellCommand::Detach(record.id));
    assert!(app.kb_view.attachments.is_empty());
}

#[test]
fn kb_records_url_metadata_without_fetching() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::KnowledgeBase(Some("x-ray".to_string())));
    app.handle_command(ShellCommand::Attach(
        "https://example.test/x-ray-notes".to_string(),
    ));

    let record = app
        .kb_view
        .attachments
        .iter()
        .find(|record| record.module_id == "x-ray")
        .unwrap();
    assert!(record.metadata_only);
    assert!(record.status.contains("not fetched"));
    assert_eq!(record.content_hash, None);
}

#[test]
fn kb_rejects_unsafe_paths_and_unknown_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.handle_command(ShellCommand::KnowledgeBase(Some("unknown".to_string())));
    let unknown_module = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(unknown_module.contains("Supported KB modules"));

    app.handle_command(ShellCommand::Attach(outside.path().display().to_string()));
    let unsafe_path = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(unsafe_path.contains("escapes workspace root"));
}

#[test]
fn options_command_resolves_default_tool_and_set_updates_session_store() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(tmp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.option_store = ToolOptionStore::new();

    app.handle_command(ShellCommand::Use("context".to_string()));
    app.handle_command(ShellCommand::Options {
        tool: None,
        filter: OptionsFilter::Standard,
    });
    app.handle_command(ShellCommand::SetOption {
        global: false,
        name: "sampleLimit".to_string(),
        value: "1".to_string(),
    });
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: None,
    });
    drain_tool(&mut app);

    let snapshot =
        fs::read_to_string(kuzushi_core::context_snapshot_path(workspace.root())).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(snapshot["filesSample"].as_array().unwrap().len(), 1);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "set" && line.body.contains("context:build.sampleLimit")));
}

#[test]
fn setg_and_unsetg_apply_global_shell_options() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Options {
        tool: Some("sast:scan".to_string()),
        filter: OptionsFilter::Standard,
    });
    app.handle_command(ShellCommand::SetOption {
        global: true,
        name: "triage".to_string(),
        value: "true".to_string(),
    });

    let prepared = app
        .registry
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
        .unwrap();
    assert_eq!(prepared["triage"], serde_json::json!(true));

    app.handle_command(ShellCommand::UnsetOption {
        global: true,
        name: "triage".to_string(),
    });
    let prepared = app
        .registry
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
        .unwrap();
    assert_eq!(prepared["triage"], serde_json::json!(false));
}

#[test]
fn unknown_option_reports_closest_names_and_next_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Options {
        tool: Some("context:build".to_string()),
        filter: OptionsFilter::Standard,
    });
    app.handle_command(ShellCommand::SetOption {
        global: false,
        name: "sampleLmit".to_string(),
        value: "1".to_string(),
    });

    let error = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("Closest: sampleLimit"));
    assert!(error.contains("Next: show options context:build"));
}

#[test]
fn auth_provider_backend_model_and_cost_commands_are_explicit_and_secret_safe() {
    let mut config = V2Config::default();
    config.runtime.api_key_env = "KUZUSHI_BG011_TEST_SECRET".to_string();
    config.model = Some("openai:gpt-4.1".to_string());
    let mut app = ShellApp::new(config, None);

    app.handle_command(ShellCommand::Auth);
    let auth = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "auth")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(auth.contains("KUZUSHI_BG011_TEST_SECRET"));
    assert!(auth.contains("secret values hidden"));
    assert!(auth.contains("openai oauth"));
    assert!(!auth.contains("sk-"));

    app.handle_command(ShellCommand::AuthLogin(Some("not-a-provider".to_string())));
    assert_eq!(app.shell_view, ShellView::Auth);
    assert!(app.log.iter().any(|line| {
        line.prefix == "error" && line.body.contains("unsupported auth login provider")
    }));

    app.handle_command(ShellCommand::Provider(None));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "provider" && line.body.contains("openai") }));

    app.handle_command(ShellCommand::Backend(Some("not-a-backend".to_string())));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "error" && line.body.contains("Supported: LangGraph") }));

    app.handle_command(ShellCommand::Model(Some("gpt-4.1".to_string())));
    assert_eq!(app.config.model.as_deref(), Some("openai:gpt-4.1"));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "error" && line.body.contains("provider:model") }));

    app.handle_command(ShellCommand::Model(Some("openai:gpt-4.1-mini".to_string())));
    assert_eq!(app.config.model.as_deref(), Some("openai:gpt-4.1-mini"));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "model" && line.body.contains("no fallback model") }));

    app.handle_command(ShellCommand::Model(Some("1 xtrahigh".to_string())));
    assert_eq!(app.config.model.as_deref(), Some("openai:gpt-5.5"));
    assert_eq!(app.session_thinking_level.as_deref(), Some("xhigh"));

    app.handle_command(ShellCommand::Use("randori".to_string()));
    app.handle_command(ShellCommand::Model(Some("5 high".to_string())));
    let stored = app.option_store.effective_stored_values("randori:pasta");
    assert_eq!(
        stored.get("model").and_then(serde_json::Value::as_str),
        Some("anthropic:claude-sonnet-4-6")
    );
    assert_eq!(
        stored.get("effort").and_then(serde_json::Value::as_str),
        Some("high")
    );

    app.last_tool_cost_usd = Some(0.0123);
    app.session_cost_usd = 0.0456;
    app.handle_command(ShellCommand::Cost);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "cost" && line.body.contains("session estimate $0.0456") }));
}

#[cfg(unix)]
#[test]
fn auth_login_status_messages_cover_success_failure_and_spawn_error() {
    use std::os::unix::process::ExitStatusExt;

    assert_eq!(auth_login_process_provider_arg("openai-codex"), "openai");
    assert_eq!(auth_login_process_provider_arg("anthropic"), "anthropic");

    let (prefix, success) = auth_login_status_message(
        "anthropic",
        "browser",
        Ok(std::process::ExitStatus::from_raw(0)),
    );
    assert_eq!(prefix, "auth");
    assert!(success.contains("Next: model 5"));

    let (prefix, openai_success) = auth_login_status_message(
        "openai-codex",
        "browser",
        Ok(std::process::ExitStatus::from_raw(0)),
    );
    assert_eq!(prefix, "auth");
    assert!(openai_success.contains("Next: model 3 (openai-oauth:gpt-5.4)"));
    assert!(!openai_success.contains("openai-codex"));
    assert!(!openai_success.contains("codex"));

    let (prefix, failed) = auth_login_status_message(
        "openai-codex",
        "headless",
        Ok(std::process::ExitStatus::from_raw(1 << 8)),
    );
    assert_eq!(prefix, "error");
    assert!(failed.contains("exited"));
    assert!(failed.contains("openai OAuth"));

    let (prefix, spawn) = auth_login_status_message(
        "openai-codex",
        "browser",
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
    );
    assert_eq!(prefix, "error");
    assert!(spawn.contains("could not start"));
}

#[test]
fn doctor_verb_points_to_cli_not_ask_agent() {
    // P4-5: typing `doctor` previously hit
    // `unknown command "doctor". Free-form chat is explicit only.
    //  Next: /ask <question> or help`
    // which sent operators into the agent path when they actually wanted
    // the diagnostic. The hint now identifies the CLI verb.
    let message = unknown_command_message("doctor");
    assert!(message.contains("CLI subcommand"));
    assert!(message.contains("kuzushi doctor"));
    assert!(!message.contains("Free-form chat"));

    let message = unknown_command_message("pr-comment");
    assert!(message.contains("CLI subcommand"));
    assert!(message.contains("kuzushi pr-comment"));
    assert!(!message.contains("Free-form chat"));

    // Plain unknown verb still uses the agent-path fallback.
    let message = unknown_command_message("zzwombat");
    assert!(message.contains("Free-form chat"));
}

#[test]
fn legacy_openai_oauth_auth_selectors_point_to_public_login_command() {
    let cases = [
        format!("auth {}", "codex"),
        format!("auth {}", "openai-codex"),
        format!("auth login {}", "codex"),
        format!("auth login {}", "openai-codex"),
        "auth legacy-openai-oauth".to_string(),
    ];
    for raw in cases {
        let message = unknown_command_message(&raw);
        assert!(message.contains("auth login openai"), "{raw}: {message}");
        assert!(!message.contains("openai-codex"), "{raw}: {message}");
        assert!(!message.contains("codex"), "{raw}: {message}");
    }
}

#[test]
fn open_store_refuses_to_silently_assume_cwd_target() {
    // M1 §1.3: typing `findings` with no target used to silently flip
    // target from None to cwd, which is dangerous for bug-bounty work
    // where scope discipline matters. open_store now errors with an
    // actionable hint and never mutates self.target.
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(app.target.is_none());
    let result = app.open_store();
    let err = match result {
        Ok(_) => panic!("open_store must refuse when no target is set"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("no target set"),
        "error must instruct the operator how to recover, got: {message}"
    );
    assert!(message.contains("target ."));
    assert!(app.target.is_none(), "self.target must not be mutated");
}

#[test]
fn bare_open_verb_suggests_findings_workflow() {
    let message = unknown_command_message("open");
    assert!(message.contains("findings"));
    assert!(message.contains("open F-0001"));
}

#[test]
fn bare_arg_taking_verbs_suggest_their_real_syntax() {
    // P-NEW-12: typing the verb without an argument used to fall through
    // to the agent-path hint. Each verb now answers with its own
    // discovery + invocation sentence.
    let cases = [
        ("since", "since main"),
        ("replay", "show runs"),
        ("trace", "show runs"),
        ("use", "modules"),
        ("run", "tools"),
    ];
    for (verb, marker) in cases {
        let message = unknown_command_message(verb);
        assert!(
            message.contains(marker),
            "{verb:?} hint missing {marker:?}: {message}"
        );
        assert!(
            !message.contains("Free-form chat"),
            "{verb:?} fell through to agent-path: {message}"
        );
    }
}

#[test]
fn findings_alias_typo_suggests_open() {
    // P-NEW-4: `findings F-0001` is a natural way to ask "show me this
    // finding" but it actually meant `open F-0001`. The unknown-command
    // hint now spots the alias and tells the operator the right verb.
    let message = unknown_command_message("findings F-0001");
    assert!(message.contains("`open F-0001`"));
    assert!(!message.contains("Free-form chat"));

    let message = unknown_command_message("finding f-007");
    assert!(message.contains("`open F-007`"));

    // Plain `findings` (no F-XXXX) is a real verb so the helper should
    // never see it; verify the typo path only fires on alias args.
    let message = unknown_command_message("findings random");
    assert!(message.contains("Free-form chat"));
}

#[test]
fn ctrl_l_clears_conversation_and_preserves_input() {
    // Industry-standard muscle memory (bash/zsh): Ctrl+L clears the
    // screen while keeping any partially typed command intact.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log("scan", "noise from earlier work");
    let log_count_before = app.log.len();
    assert!(log_count_before > 1);

    // Mid-command Ctrl+L: log clears, input survives, no stray 'l'.
    app.set_input("scan ./repo");
    let cursor_before = app.cursor;
    app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));
    assert_eq!(app.input, "scan ./repo");
    assert_eq!(app.cursor, cursor_before);
    assert!(app.log.len() < log_count_before);
    assert!(app
        .log
        .iter()
        .any(|line| line.body.contains("Conversation cleared")));
}

#[test]
fn empty_input_enter_does_not_log_or_grow_history() {
    // P-NEW-3: pressing Enter on an empty / whitespace-only prompt used
    // to push a `>` bullet with no body into the transcript and waste
    // a precious row in the 2-row strip. The submit is now a no-op:
    // no log, no history entry.
    let mut app = ShellApp::new(V2Config::default(), None);
    let log_count = app.log.len();
    let history_count = app.command_history.len();

    app.submit_line("");
    app.submit_line("    ");
    app.submit_line("\t \t");

    assert_eq!(app.log.len(), log_count);
    assert_eq!(app.command_history.len(), history_count);
}

#[test]
fn options_dot_resolves_to_focused_module_primary_tool() {
    // The module-view footer advertises `help options . · prompts ·
    // tune · back`, but `options .` errored with `unknown tool "."`
    // because "." was looked up directly. Now it resolves to the
    // focused module's primary tool, mirroring `run .`.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("codeql".to_string());
    let resolved = app
        .resolve_options_tool(Some(".".to_string()))
        .expect("`options .` with codeql focused should resolve");
    assert_eq!(resolved, "codeql:scan");

    // Without a focused module the helper produces a useful error so
    // the user knows to `use <module>` first.
    app.focused_module = None;
    let err = app
        .resolve_options_tool(Some(".".to_string()))
        .expect_err("`options .` without focus should fail");
    assert!(err.to_string().contains("requires a focused module"));
}

#[test]
fn options_accepts_bare_module_id() {
    // Operators type `options semgrep` (a module), not `options semgrep:scan`.
    let app = ShellApp::new(V2Config::default(), None);
    let resolved = app
        .resolve_options_tool(Some("semgrep".to_string()))
        .expect("a bare module id should resolve to its primary tool");
    assert_eq!(resolved, "semgrep:scan");

    let err = app
        .resolve_options_tool(Some("does-not-exist".to_string()))
        .expect_err("an unknown name should error helpfully");
    assert!(err.to_string().contains("tools"));
}

#[test]
fn tab_cycles_through_completion_candidates() {
    // P3-3: Tab used to commit only the first candidate and then no-op
    // forever. With 35 modules, cycling is the only way to discover the
    // catalog from the keyboard. Verify Tab walks the candidate list
    // and wraps around, and that any non-Tab key resets the cycle so a
    // fresh keystroke on the next Tab generates new candidates.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("use s");

    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    let first = app.input.clone();
    assert!(
        first.starts_with("use s"),
        "expected use s* candidate, got {first:?}"
    );

    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    let second = app.input.clone();
    assert_ne!(
        first, second,
        "second Tab should advance to a different module"
    );
    assert!(second.starts_with("use s"));

    // Many modules begin with "s" (sast, secret-scan, semgrep, shinsa,
    // smoke, systems-hunt). After enough Tabs we should wrap to the
    // first candidate again.
    let mut seen = vec![first.clone(), second.clone()];
    for _ in 0..50 {
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
        seen.push(app.input.clone());
        if app.input == first && seen.len() > 2 {
            break;
        }
    }
    assert!(
        seen.iter().filter(|s| **s == first).count() >= 2,
        "expected to wrap back to first candidate; saw {seen:?}"
    );

    // A regular character resets the cycle so the next Tab uses the new
    // prefix instead of continuing from the old candidate list.
    app.set_input("use c");
    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()));
    assert!(app.completion_cycle.is_none());
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert!(
        app.input.starts_with("use co"),
        "Tab after 'use co' should pick a co* candidate, got {:?}",
        app.input
    );
}

#[test]
fn esc_during_active_completion_cycle_restores_original_prefix() {
    // M3 §3.3: when the operator types a partial command and presses
    // Tab, a completion cycle starts. Esc must close the popup AND put
    // the original prefix back so the operator doesn't lose what they
    // typed. The clear-on-Esc draft stash is reserved for the non-cycle
    // case.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("sca");
    let prefix = app.input.clone();
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert!(
        app.completion_cycle.is_some(),
        "Tab must open a completion cycle when candidates are available"
    );
    assert_ne!(app.input, prefix, "Tab applied the first candidate");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert!(app.completion_cycle.is_none(), "Esc closes the cycle");
    assert_eq!(
        app.input, prefix,
        "Esc must restore the operator's typed prefix"
    );
}

#[test]
fn esc_stashes_input_and_one_more_esc_restores_it() {
    // P3-2: previously Esc wiped the input with no recovery, so a long
    // command typed and then Esc'd was lost forever (Up arrow restores
    // history, not the most recent draft). Now Esc stashes the draft and
    // a second Esc on an empty prompt restores it.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("scan ./very/specific/path with --since main --include-worktree");
    let original = app.input.clone();
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.input.is_empty(), "first Esc clears the input");
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.input, original, "second Esc restores the draft");
    assert_eq!(app.cursor, original.chars().count());

    // Restoring consumed the stash; a third Esc cycle starts fresh.
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.input.is_empty(), "third Esc clears again");
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(
        app.input, original,
        "fourth Esc restores the new stash (which was the second clear)"
    );
}

#[test]
fn model_choice_with_focused_module_and_no_global_sets_global_first() {
    // P5-2: previously `model 5` while focused on a module set the
    // per-module option only and left config.model None, trapping the
    // operator behind "ask requires an explicit model" the moment they
    // typed `?question`. Now the first `model <n>` becomes global so
    // the agent path has something to dispatch with; subsequent
    // `model <n>` calls scope per-module.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("sast".to_string());
    assert!(app.config.model.is_none());

    app.handle_command(ShellCommand::Model(Some("5".to_string())));
    assert_eq!(
        app.config.model.as_deref(),
        Some("anthropic:claude-sonnet-4-6"),
        "first model selection with focused module must set global so /ask works"
    );

    // After a global is set, the next `model <n>` scopes per-module so
    // operators can override per-tool without losing the global default.
    app.handle_command(ShellCommand::Model(Some("6".to_string())));
    assert_eq!(
        app.config.model.as_deref(),
        Some("anthropic:claude-sonnet-4-6"),
        "second model selection must NOT clobber the global"
    );
    let module_values = app
        .option_store
        .values_for(
            OptionScope::Session,
            &OptionTarget::Module("sast".to_string()),
        )
        .expect("expected per-module options after second selection");
    let module_model = module_values
        .get("model")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    assert_eq!(
        module_model.as_deref(),
        Some("anthropic:claude-opus-4-7"),
        "second selection must scope to the focused module"
    );
}

#[test]
fn config_view_onboards_with_keyboard_model_selection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Config;
    // The Config view hides the non-primary OpenAI row (which varies with auth
    // state), so navigation steps the *visible* set — derive expectations from
    // it rather than hardcoding an index, and assert the Enter target is exactly
    // the highlighted (visible) row, not a hidden one.
    let visible = super::settings::visible_model_choice_indexes(app.config.model.as_deref());
    let choices = super::settings::model_choices();
    app.selected_model_index = visible[0];

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    assert_eq!(app.selected_model_index, visible[1 % visible.len()]);

    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.selected_model_index, visible[0]);

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    let expected = choices[visible[0]];
    assert_eq!(app.config.model.as_deref(), Some(expected.id));
    assert_eq!(
        app.session_thinking_level.as_deref(),
        Some(expected.thinking_level)
    );
    assert!(
        app.log
            .iter()
            .any(|line| line.prefix == "model"
                && line.body.contains("showing config, Esc to go back"))
    );
}

#[test]
fn auth_picker_navigation_keys_work_with_text_in_prompt() {
    // Regression: the picker used to bail whenever the input buffer was
    // non-empty, so a stray character silently stole j/k/Enter. As a true
    // modal it now captures navigation regardless of prompt contents.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::AuthMethodPicker("openai".to_string());
    app.auth_picker_cursor = 0;
    app.input = "leftover".to_string();

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.auth_picker_cursor, 1, "j must move the picker cursor");
    assert_eq!(app.input, "leftover", "navigation must not edit the prompt");
}

#[test]
fn auth_picker_swallows_typed_characters() {
    // Printable keys are consumed by the modal so they never leak into the
    // prompt and quietly disarm the navigation keys.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::AuthMethodPicker("anthropic".to_string());
    app.input.clear();

    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()));
    assert!(app.input.is_empty(), "picker must swallow typed characters");
}

#[test]
fn auth_picker_swallows_shifted_typed_characters() {
    // Some terminals deliver uppercase printables as Char + SHIFT. Those are
    // still plain picker input, not shell chords.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::AuthMethodPicker("openai".to_string());

    app.handle_key(KeyEvent::new(KeyCode::Char('H'), KeyModifiers::SHIFT));
    assert!(
        app.input.is_empty(),
        "picker must swallow shifted printable characters"
    );
}

#[test]
fn picker_footer_omits_tab_complete_hint() {
    // Tab does nothing in a modal picker, so the footer must not claim it
    // completes — that contradicted the picker's own hint row.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::AuthMethodPicker("openai".to_string());
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(
        !bindings.iter().any(|binding| binding.key == "Tab"),
        "picker footer must not advertise Tab complete"
    );
}

#[test]
fn ask_requires_explicit_model_and_unknown_prose_stays_deterministic() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;

    app.handle_command(parse_command("summarize this repo"));

    assert_eq!(app.shell_view, ShellView::Home);
    assert!(app.agent_chat.is_none());
    assert!(app.log.iter().any(|line| {
        line.prefix == "error" && line.body.contains("Free-form chat is explicit only")
    }));

    app.handle_command(parse_command("/ask What should I run first?"));

    assert_eq!(app.shell_view, ShellView::AgentChat);
    let agent = app.agent_chat.as_ref().unwrap();
    assert_eq!(agent.question, "What should I run first?");
    assert!(!agent.running);
    assert!(agent
        .error
        .as_deref()
        .is_some_and(|error| error.contains("explicit model")));
}

#[test]
fn exit_and_unknown_command_feedback_is_actionable() {
    for command in ["/exit", "exit", "/exitj"] {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.submit_line(command);

        assert!(app.should_quit, "{command} should request shutdown");
        assert!(app.agent_chat.is_none());
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == ">" && line.body == command));
        assert!(app.log.iter().any(|line| {
            line.prefix == "system" && line.body.contains("exit requested; closing shell")
        }));
    }

    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;
    app.submit_line("/definitely-not-real");
    let slash_error = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(slash_error.contains("Next: /help"));
    assert!(app.agent_chat.is_none());
    assert!(!app.should_quit);

    app.submit_line("ask");
    let missing_ask_error = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(missing_ask_error.contains("Next: /ask <question>"));
    assert!(app.agent_chat.is_none());
    assert_eq!(app.shell_view, ShellView::Home);
}

#[test]
fn plain_scripted_unknown_command_prints_command_and_new_error_log() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;

    let output = render_plain_scripted_session(&mut app, &["/nope"], 80);

    assert!(output.contains("COMMAND RESULT"));
    assert!(output.contains("command: /nope"));
    assert!(output.contains("> /nope"));
    assert!(output.contains("error: unknown command \"/nope\". Next: /help"));
    assert_eq!(app.shell_view, ShellView::Home);
    assert_plain_output_strict_80(&output);
}

#[test]
fn plain_scripted_quit_prints_exit_acknowledgement() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let output = render_plain_scripted_session(&mut app, &["/quit"], 80);

    assert!(app.should_quit);
    assert!(output.contains("command: /quit"));
    assert!(output.contains("> /quit"));
    assert!(output.contains("system: exit requested; closing shell"));
    assert_plain_output_strict_80(&output);
}

#[test]
fn plain_scripted_help_then_quit_prints_one_result_block_per_command() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let output = render_plain_scripted_session(&mut app, &["/help", "/quit"], 80);

    assert!(app.should_quit);
    assert_eq!(output.matches("COMMAND RESULT").count(), 2);
    assert!(output.contains("command: /help"));
    assert!(output.contains("command: /quit"));
    assert!(output.contains("HELP"));
    assert!(output.contains("system: exit requested; closing shell"));
    assert_plain_output_strict_80(&output);
}

#[test]
fn plain_scripted_unchanged_view_command_still_prints_result_block() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;
    let before = app.shell_view.clone();

    let output = render_plain_scripted_session(&mut app, &["/back"], 80);

    assert_eq!(app.shell_view, before);
    assert!(output.contains("COMMAND RESULT"));
    assert!(output.contains("command: /back"));
    assert!(output.contains("> /back"));
    assert!(output.contains("HOME"));
    assert!(output.contains("modules"));
    assert_plain_output_strict_80(&output);
}

#[test]
fn session_history_clear_load_resume_pause_and_story_are_explicit() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.submit_line("modules");
    app.submit_line("/history");

    assert_eq!(app.shell_view, ShellView::History);
    assert_eq!(
        app.command_history,
        vec!["modules".to_string(), "/history".to_string()]
    );
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "history" && line.body.contains("2 command")));

    app.submit_line("/clear");

    assert_eq!(
        app.command_history,
        vec![
            "modules".to_string(),
            "/history".to_string(),
            "/clear".to_string()
        ]
    );
    assert_eq!(app.log.len(), 1);
    assert!(app.log[0].body.contains("Conversation cleared"));

    app.handle_command(parse_command("/load builtin:sast"));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "load" && line.body.contains("already available") }));

    app.handle_command(parse_command("/load file:///tmp/module.js"));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "error" && line.body.contains("is not trusted") }));

    app.handle_command(parse_command("/pause"));
    assert!(app.log.iter().any(|line| {
        line.prefix == "pause" && line.body.contains("no live pause/resume control")
    }));

    app.handle_command(parse_command("/resume run-123"));
    assert_eq!(app.shell_view, ShellView::Replay("run-123".to_string()));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "resume" && line.body.contains("replay run-123") }));

    app.handle_command(parse_command("/story"));
    assert_eq!(app.shell_view, ShellView::Story);
}

#[cfg(unix)]
#[test]
fn ask_dispatches_agent_question_through_explicit_runtime() {
    let tmp = tempfile::tempdir().unwrap();
    let bridge = fake_ask_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "KUZUSHI_TEST_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };
    let mut app = ShellApp::new(config, None);
    app.target = Some(tmp.path().to_path_buf());

    app.handle_command(parse_command("?What should I run first?"));

    assert_eq!(app.shell_view, ShellView::AgentChat);
    let running_agent = app.agent_chat.as_ref().unwrap();
    assert_eq!(running_agent.question, "What should I run first?");
    assert!(
        running_agent.running,
        "ask should enter AgentChat running state immediately; {}",
        app.agent_chat_diagnostics_for_test()
    );
    assert_eq!(running_agent.answer, None);
    assert_eq!(running_agent.error, None);

    app.drain_next_agent_event_for_test(Duration::from_secs(5))
        .unwrap_or_else(|message| panic!("{message}"));

    let agent = app.agent_chat.as_ref().unwrap();
    assert!(
        !agent.running,
        "ask worker completed but AgentChat remained running; {}",
        app.agent_chat_diagnostics_for_test()
    );
    assert!(
        agent.error.is_none(),
        "ask worker failed instead of answering: {}",
        app.agent_chat_diagnostics_for_test()
    );
    assert_eq!(
        agent.answer.as_deref(),
        Some("Run context build, then scan ."),
        "ask worker completed with wrong UI state; {}",
        app.agent_chat_diagnostics_for_test()
    );
    let run_id = agent.run_id.as_deref().unwrap();
    let summary = load_run_summary(tmp.path(), run_id).unwrap();
    assert_eq!(summary.llm_calls.len(), 1);
    assert_eq!(summary.llm_calls[0].model, "openai:gpt-4.1");
    assert_eq!(summary.llm_calls[0].provider, "openai");
    assert!(summary.llm_calls[0].prompt_hash.starts_with("fnv1a64:"));
    assert_eq!(summary.llm_calls[0].cost_usd, Some(0.034));
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "answer" && line.body.contains("Run context build") }));
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_recon_nmap_through_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let binary = fake_nmap_binary(&tmp.path().to_path_buf());
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("recon:nmap".to_string()),
        input: Some(format!(
            r#"{{"target":"192.0.2.10","ports":"80,443","binary":"{}"}}"#,
            binary.display()
        )),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result"
            && line
                .body
                .contains("recon:nmap discovered 1 host and 2 open services")
    }));
    let mut store = kuzushi_core::ReconWorkspaceStore::open(&workspace).unwrap();
    let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
    let hosts = store.list_hosts(&workspace_id).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_recon_http_fingerprint_through_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let binary = fake_curl_binary(&tmp.path().to_path_buf());
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("recon:http-fingerprint".to_string()),
        input: Some(format!(
            r#"{{"target":"https://www.example.com","binary":"{}"}}"#,
            binary.display()
        )),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result"
            && line
                .body
                .contains("recon:http-fingerprint registered https://www.example.com")
    }));
    let mut store = kuzushi_core::ReconWorkspaceStore::open(&workspace).unwrap();
    let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
    let hosts = store.list_hosts(&workspace_id).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 1);
}

#[test]
fn run_command_dispatches_secret_scan_through_registry() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.env"),
        [
            "OPENAI_API_KEY=",
            "sk",
            "-proj-",
            "abcdefghijklmnopqrstuvwxyzABCDEFGH",
        ]
        .concat(),
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("secret-scan".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: None,
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "result" && line.body.contains("secret-scan: 1 finding") }));
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_semgrep_through_registry_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("server.js"), "res.send(req.query.x)\n").unwrap();
    let binary = fake_semgrep_binary(&tmp.path().to_path_buf());
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("semgrep".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(format!(
            r#"{{"binary":"{}","config":"p/security-audit"}}"#,
            binary.display()
        )),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("semgrep: 1 finding")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_codeql_through_registry_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
    fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
    let binary = fake_codeql_binary(&tmp.path().to_path_buf());
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("codeql".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(format!(
            r#"{{"binary":"{}","language":"javascript"}}"#,
            binary.display()
        )),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("codeql: 1 finding")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
}

#[test]
fn run_command_dispatches_iac_scan_through_registry_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("main.tf"),
        "cidr_blocks = [\"0.0.0.0/0\"]\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("iac-scan".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"kind":"terraform"}"#.to_string()),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("iac-scan: 1 finding")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "iac-scan");
}

#[test]
fn run_command_dispatches_cargo_audit_through_registry() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Use("cargo-audit".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: None,
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result" && line.body.contains("cargo-audit: 0 advisory findings")
    }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store.list_findings(10).unwrap().is_empty());
}

#[test]
fn run_command_dispatches_sast_scan_through_registry_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("config.env"),
        [
            "OPENAI_API_KEY=",
            "sk",
            "-proj-",
            "abcdefghijklmnopqrstuvwxyzABCDEFGH",
        ]
        .concat(),
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.trusted_workflow_auto_accept = true;
    app.handle_command(ShellCommand::Use("sast".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#.to_string()),
    });
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("sast:scan")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 2);
}

#[test]
fn run_dot_from_catalog_dispatches_sast_scan() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("config.env"),
        [
            "OPENAI_API_KEY=",
            "sk",
            "-proj-",
            "abcdefghijklmnopqrstuvwxyzABCDEFGH",
        ]
        .concat(),
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.trusted_workflow_auto_accept = true;
    app.handle_command(parse_command(
        r#"run . {"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#,
    ));
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.focused_module.is_none());
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "tool" && line.body.contains("running sast:scan")));
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("sast:scan")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_agentic_sast_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_agentic_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.trusted_workflow_auto_accept = true;
    app.handle_command(ShellCommand::Use("agentic-sast".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"maxFindings":5}"#.to_string()),
    });
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "result" && line.body.contains("agentic-sast: 1 finding") }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "agentic");
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_variant_hunt_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
    fs::write(tmp.path().join("src/other.ts"), "exec(req.body.other)\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let fingerprint = seed_true_positive_finding(&workspace);
    let bridge = fake_variant_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("variant".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(format!(
            r#"{{"fingerprint":"{fingerprint}","maxFindings":5}}"#
        )),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "result" && line.body.contains("variant:hunt complete") }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding.tool == "variant-analysis"));
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_ndiff_hunt_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/parser.c"), "memcpy(dst, src, len)\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_ndiff_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("ndiff".to_string()));
    app.handle_command(ShellCommand::RunTool {
            tool: Some("hunt-variants".to_string()),
            input: Some(
                r#"{"advisoryId":"CVE-2024-1234","pattern":{"fixShape":"adds a bounds check before memcpy","vulnerableShape":"memcpy uses attacker-controlled length without a bounds check","cwe":["CWE-787"],"languages":["c"],"keywords":["memcpy","len"],"detectionQuery":"rg 'memcpy\\('","description":"Search copies guarded by no length cap.","confidence":"HIGH"}}"#
                    .to_string(),
            ),
        });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result" && line.body.contains("ndiff:hunt-variants complete")
    }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding.tool == "n-day-diff-hunter"));
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_taint_iris_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_taint_iris_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.trusted_workflow_auto_accept = true;
    app.handle_command(ShellCommand::Use("taint-iris".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"maxFindings":5}"#.to_string()),
    });
    drain_chain_with_auto_reuse(&mut app);

    // Auto-open lands on the attack-path page once the taint flow is generated.
    assert_eq!(
        app.shell_view,
        ShellView::Scene(crate::scene3d::VizPage::AttackPath)
    );
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "result" && line.body.contains("taint-iris: 1 finding") }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris");
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_legacy_taint_iris_next_hunt_through_langgraph_runtime_bridge_and_persists(
) {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("src/routes.ts"),
        "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
    )
    .unwrap();
    // taint-iris-next:hunt now requires CPG + CodeQL DB artifacts to
    // attach the joern/codeql MCPs. Stub both so the policy probe
    // returns the expected attachments and the hunt routes.
    let kuzushi = tmp.path().join(".kuzushi");
    fs::create_dir_all(&kuzushi).unwrap();
    fs::write(kuzushi.join("cpg.bin"), b"CPG\0stub").unwrap();
    let codeql_db = kuzushi.join("codeql-db");
    fs::create_dir_all(&codeql_db).unwrap();
    fs::write(codeql_db.join("placeholder"), "stub").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_taint_iris_next_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.trusted_workflow_auto_accept = true;
    app.handle_command(ShellCommand::Use("taint-iris-next".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("taint-iris-next:hunt".to_string()),
        input: Some(
            r#"{"mode":"hunt","maxCatalogEntries":3,"maxAgentFindings":5,"minEvidenceLevel":"candidate"}"#
                .to_string(),
        ),
    });
    drain_chain_with_auto_reuse(&mut app);

    // taint-iris-next flattens its taint path into finding text and emits no
    // structured `data.flows[]`, so there's nothing for the attack-path page to
    // draw — auto-open correctly leaves the view on Activity.
    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(
        app.log.iter().any(|line| {
            line.prefix == "result"
                && line.body.contains("Taint IRIS Next")
                && line.body.contains("hunt complete")
        }),
        "expected Taint IRIS Next hunt result log"
    );

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_carlini_threat_hunt_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(
        tmp.path().join("src/app.ts"),
        "res.send(`<p>${req.query.name}</p>`)\n",
    )
    .unwrap();
    write_carlini_threat_model_fixture(&tmp.path().to_path_buf());
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_carlini_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("carlini-threat-hunt:run".to_string()),
        input: Some(r#"{"maxActors":1,"runsPerActor":1}"#.to_string()),
    });
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result" && line.body.contains("carlini-threat-hunt: 1 finding")
    }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "carlini-threat-hunt");
    assert_eq!(
        findings[0].actor_fingerprint.as_deref(),
        Some("carlini-threat-hunt:Authenticated_User:0")
    );
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_systems_hunt_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    write_systems_hunt_fixture(&tmp.path().to_path_buf());
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_systems_hunt_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("systems-hunt:systems-hunt".to_string()),
        input: Some(r#"{"maxFindings":5}"#.to_string()),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "result" && line.body.contains("systems-hunt: 1 finding") }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "systems-hunt");
}

#[test]
fn run_command_dispatches_findings_filters_through_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        12,
        Some(12),
        Severity::High,
        "SQL injection in search",
    );
    let finding_id = store.insert_finding("run-1", &finding).unwrap();
    store
        .save_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.9,
                rationale: "confirmed".to_string(),
                ..Default::default()
            },
        )
        .unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("findings:list".to_string()),
        input: Some(r#"{"severity":["high"],"verdict":["tp"],"name":"sql"}"#.to_string()),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app.log.iter().any(|line| {
        line.prefix == "result"
            && line.body.contains("SQL injection in search")
            && line.body.contains("1 matching")
    }));
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_triage_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        12,
        Some(12),
        Severity::High,
        "SQL injection in search",
    );
    store.insert_finding("run-1", &finding).unwrap();
    let bridge = fake_triage_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("triage".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint)),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("Triaged 1 of 1")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let stored = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::TruePositive)
    );
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_verify_through_langgraph_runtime_bridge() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        12,
        Some(12),
        Severity::High,
        "SQL injection in search",
    );
    let finding_id = store.insert_finding("run-1", &finding).unwrap();
    store
        .save_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.9,
                rationale: "confirmed".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    let bridge = fake_verify_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("verify".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint)),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("VULNERABLE")));
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("curl POST /admin")));
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_patch_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/db.ts"), "const query = req.query.q;\n").unwrap();
    init_git_repo(&tmp.path().to_path_buf());

    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        1,
        Some(1),
        Severity::High,
        "SQL injection in search",
    );
    let finding_id = store.insert_finding("run-1", &finding).unwrap();
    store
        .save_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.9,
                rationale: "confirmed".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    let bridge = fake_patch_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("patch".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(format!(
            r#"{{"fingerprint":"{}","maxIterations":1,"buildCmd":"true","testCmd":"true"}}"#,
            finding.fingerprint
        )),
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("patch:finding SOUND")));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let patch_results = store
        .get_patch_results_for_finding(&finding.fingerprint)
        .unwrap();
    assert_eq!(patch_results.len(), 1);
    assert_eq!(patch_results[0].status.as_str(), "SOUND");
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_threat_model_build_through_langgraph_runtime_bridge() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"express":"4"}}"#,
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_threat_model_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("threat-model".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: None,
        input: Some(r#"{"outputDir":".kuzushi/tm"}"#.to_string()),
    });
    drain_chain_with_auto_reuse(&mut app);

    // Auto-open lands on the data-flow diagram once the threat model is built.
    assert_eq!(
        app.shell_view,
        ShellView::Scene(crate::scene3d::VizPage::Dfd)
    );
    assert!(app.log.iter().any(|line| {
        line.prefix == "result" && line.body.contains("threat-model:build complete")
    }));
    assert!(kuzushi_core::capabilities::persistent_threat_model_path(tmp.path()).exists());
    assert!(tmp
        .path()
        .join(".kuzushi/tm/normalized-threat-model.json")
        .exists());
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_x_ray_run_through_langgraph_runtime_bridge() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("README.md"), "# app\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let bridge = fake_x_ray_bridge(&tmp.path().to_path_buf());
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".to_string());
    config.runtime = RuntimeConfig {
        kind: RuntimeKind::LangGraph,
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.handle_command(ShellCommand::Use("x-ray".to_string()));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("x-ray:run".to_string()),
        input: None,
    });
    drain_tool(&mut app);

    assert_eq!(app.shell_view, ShellView::Activity);
    assert!(app
        .log
        .iter()
        .any(|line| { line.prefix == "result" && line.body.contains("x-ray:run complete") }));
    assert!(workspace.root().join("x-ray/x-ray.md").exists());
    assert!(workspace.root().join("x-ray/architecture.svg").exists());
}

#[test]
fn open_command_selects_finding_by_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "dangerous sink",
    );
    store.insert_finding("run-1", &finding).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.handle_command(ShellCommand::Open(finding.fingerprint[..8].to_string()));

    assert_eq!(
        app.selected_finding
            .as_ref()
            .map(|finding| &finding.fingerprint),
        Some(&finding.fingerprint)
    );
}

#[test]
fn ctrl_c_requests_active_scan_abort_before_exit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert!(!app.should_quit);
    assert_eq!(
        app.scan.as_ref().map(|scan| scan.stage.as_str()),
        Some("abort requested")
    );
    assert!(app.scan.as_ref().is_some_and(|scan| scan.abort_requested));
    assert!(app.log.iter().any(|line| {
        line.prefix == "scan"
            && line.body.contains("abort requested")
            && line.body.contains("not claiming")
    }));
}

#[test]
fn threat_digit_hotkeys_switch_views_without_entering_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Threat(ThreatView::Summary);

    app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::empty()));

    assert_eq!(app.shell_view, ShellView::Threat(ThreatView::Stride));
    assert!(app.input.is_empty());
}

#[test]
fn first_ctrl_c_at_idle_arms_without_quitting() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(!app.should_quit);
    assert!(app.ctrl_c_armed());
}

#[test]
fn second_ctrl_c_within_window_quits() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.should_quit);
}

#[test]
fn ctrl_d_also_arms_and_quits() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
    assert!(app.ctrl_c_armed());
    assert!(!app.should_quit);
    app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
    assert!(app.should_quit);
}

#[test]
fn any_other_key_disarms() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.ctrl_c_armed());
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()));
    assert!(!app.ctrl_c_armed());
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(!app.should_quit);
}

#[test]
fn arm_window_expires_via_tick() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ctrl_c_armed_at = Some(Instant::now() - (CTRL_C_ARM_WINDOW + Duration::from_secs(1)));
    assert!(!app.ctrl_c_armed());
    app.tick();
    assert!(app.ctrl_c_armed_at.is_none());
}

#[test]
fn throttle_advisory_set_and_clear() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_throttle("openai", "429: backing off 2s");
    assert!(app.advisory.throttle.is_some());
    app.clear_throttle();
    assert!(app.advisory.throttle.is_none());
}

#[test]
fn throttle_advisory_expires_via_tick() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_throttle("openai", "stale");
    app.advisory.throttle.as_mut().unwrap().since =
        Instant::now() - (THROTTLE_STALE_AFTER + Duration::from_secs(1));
    app.tick();
    assert!(app.advisory.throttle.is_none());
}

#[test]
fn scan_failure_sets_error_notice_and_keeps_log() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.apply_scan_failed("semgrep not found".to_string());

    let notice = app.advisory.notice.as_ref().expect("notice surfaced");
    assert_eq!(notice.severity, crate::NoticeSeverity::Error);
    assert!(notice.message.contains("semgrep not found"));
    assert!(
        app.log.iter().any(|line| line.prefix == "error"),
        "transcript record must be preserved"
    );
}

#[test]
fn esc_dismisses_notice_before_going_back() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Tools;
    app.nav_history.push(ShellView::Catalog);
    app.set_error_notice("tool", "boom");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert!(app.advisory.notice.is_none(), "notice dismissed");
    assert_eq!(
        app.shell_view,
        ShellView::Tools,
        "back deferred to next Esc"
    );
}

#[test]
fn notice_auto_clears_after_stale_window() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_error_notice("tool", "stale");
    app.advisory.notice.as_mut().unwrap().since =
        Instant::now() - (NOTICE_STALE_AFTER + Duration::from_secs(1));
    assert!(app.tick());
    assert!(app.advisory.notice.is_none());
}

#[test]
fn multiline_paste_sets_warn_notice() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_paste("first\nsecond\nthird");

    assert_eq!(app.input, "first", "only the first line is kept");
    let notice = app.advisory.notice.as_ref().expect("paste notice surfaced");
    assert_eq!(notice.severity, crate::NoticeSeverity::Warn);
    assert!(notice.message.contains("dropped 2"));
}

#[test]
fn enter_on_empty_findings_logs_guidance() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    assert!(app.findings.is_empty());

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    assert!(
        app.log
            .iter()
            .any(|line| line.prefix == "findings" && line.body.contains("run `scan`")),
        "empty-findings Enter should guide the operator"
    );
    assert_eq!(app.shell_view, ShellView::Findings, "stay on the view");
}

#[test]
fn reverse_search_finds_and_accepts_a_past_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.command_history = vec!["scan .".to_string(), "run semgrep:scan".to_string()];

    // Ctrl+R enters search; typing narrows to the matching command.
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(app.history_search.is_some());
    for ch in "semgrep".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
    }
    assert_eq!(app.current_history_match(), Some("run semgrep:scan"));

    // Enter accepts the match into the prompt and exits search.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.history_search.is_none());
    assert_eq!(app.input, "run semgrep:scan");
}

#[test]
fn reverse_search_esc_cancels() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.command_history = vec!["scan .".to_string()];
    app.enter_history_search();
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.history_search.is_none());
    assert!(app.input.is_empty());
}

#[test]
fn command_palette_opens_filters_and_loads_without_executing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;

    // Ctrl+G opens the palette.
    app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view, ShellView::CommandPalette);

    // Typing filters the specs.
    for ch in "scan".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
    }
    let matches = app.palette_matches();
    assert!(
        matches.iter().any(|spec| spec.command.starts_with("scan")),
        "query `scan` should surface the scan command"
    );

    // Enter loads the canonical head into the prompt but does NOT execute.
    let before_log = app.log.len();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_ne!(app.shell_view, ShellView::CommandPalette, "palette closed");
    assert!(!app.input.is_empty(), "selected command loaded into prompt");
    assert!(
        !app.log
            .iter()
            .skip(before_log)
            .any(|line| line.prefix == ">"),
        "accepting must not submit the command"
    );
}

#[test]
fn command_palette_esc_closes_without_loading() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;
    app.open_command_palette();
    assert_eq!(app.shell_view, ShellView::CommandPalette);

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_ne!(app.shell_view, ShellView::CommandPalette);
    assert!(
        app.input.is_empty(),
        "Esc cancels without loading a command"
    );
}

#[test]
fn subverb_query_lists_subverbs_without_routing_to_unknown() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.submit_line("task ?");

    let listed = app
        .log
        .iter()
        .find(|line| line.prefix == "task")
        .expect("task sub-verbs listed");
    assert!(listed.body.contains("block") && listed.body.contains("mode"));
    assert!(
        !app.log
            .iter()
            .any(|line| line.body.contains("unknown command")),
        "`task ?` must not fall through to the unknown-command path"
    );
}

#[test]
fn command_history_round_trips_to_disk_per_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());

    app.submit_line("modules");
    app.submit_line("tools");

    let path = tmp.path().join(".kuzushi/v2/shell-history.txt");
    assert!(path.exists(), "history file should be written");
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("modules") && contents.contains("tools"));

    let mut reopened = ShellApp::new(V2Config::default(), None);
    reopened.target = Some(tmp.path().to_path_buf());
    reopened.load_persisted_history();
    assert_eq!(reopened.command_history, vec!["modules", "tools"]);
}

#[test]
fn history_load_caps_at_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(".kuzushi/v2/shell-history.txt");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let lines: Vec<String> = (0..(COMMAND_HISTORY_CAP + 50))
        .map(|i| format!("cmd-{i}"))
        .collect();
    std::fs::write(&path, lines.join("\n")).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.load_persisted_history();

    assert_eq!(app.command_history.len(), COMMAND_HISTORY_CAP);
    assert_eq!(app.command_history.last().unwrap(), "cmd-249");
}

#[test]
fn history_without_workspace_stays_in_memory_only() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(app.target.is_none());
    app.submit_line("modules");
    // No panic, no disk write; history is still tracked in memory.
    assert_eq!(app.command_history, vec!["modules"]);
}

#[test]
fn spinner_resets_when_work_completes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.spinner_phase = 5;
    assert!(!app.has_running_work());
    assert!(app.tick(), "completion should force one repaint");
    assert_eq!(app.spinner_phase, 0);
}

#[test]
fn running_work_shows_strip_spinner_off_activity_view() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tool_running = Some("semgrep:scan".to_string());
    app.shell_view = ShellView::Catalog;

    let model = crate::ui_view_models::context_strip_model(&app);
    let run = model.run.expect("a run segment with a spinner");
    assert!(run.value.contains("semgrep:scan"));
    assert!(run.value.contains(app.spinner_glyph()));
}

#[test]
fn budget_halt_triggers_when_cost_exceeds_cap() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_budget_usd = Some(0.10);
    app.record_cost(0.12);
    assert!(app.is_budget_halted());
    let halt = app.advisory.budget_halt.as_ref().unwrap();
    assert!(halt.spent_usd >= 0.12);
    assert_eq!(halt.limit_usd, 0.10);
}

#[test]
fn shell_uses_operator_budget_and_trusted_workflow_from_config() {
    let mut config = V2Config::default();
    config.operator.session_budget_usd = Some(1.25);
    config.operator.trusted_workflow_auto_accept = true;

    let app = ShellApp::new(config, None);

    assert_eq!(app.session_budget_usd, Some(1.25));
    assert!(app.trusted_workflow_auto_accept);
}

#[test]
fn next_command_opens_phase_picker_at_derived_phase() {
    // `next` resumes the engagement wherever the workspace actually is —
    // fresh target lands in 組 map, map artifacts move it to 崩 hunt,
    // unconfirmed findings to 作 confirm, fully confirmed to 掛 fix.
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(dir.path().to_path_buf());

    app.handle_command(ShellCommand::Next);
    assert_eq!(app.shell_view, ShellView::PlanningPicker);
    assert_eq!(app.workflow_phase, Some(WorkflowPhase::Map));

    std::fs::create_dir_all(dir.path().join(".kuzushi")).expect("kuzushi dir");
    std::fs::write(dir.path().join(".kuzushi/context-snapshot.json"), "{}")
        .expect("context snapshot");
    app.workflow_phase = None;
    app.handle_command(ShellCommand::Next);
    assert_eq!(app.workflow_phase, Some(WorkflowPhase::Hunt));

    app.findings = vec![make_finding(Severity::High, "fp-journey", "Unconfirmed")];
    app.workflow_phase = None;
    app.handle_command(ShellCommand::Next);
    assert_eq!(app.workflow_phase, Some(WorkflowPhase::Confirm));

    app.findings[0].triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.9,
        rationale: "confirmed".to_string(),
        cost_usd: 0.0,
    });
    app.workflow_phase = None;
    app.handle_command(ShellCommand::Next);
    assert_eq!(app.workflow_phase, Some(WorkflowPhase::Fix));
}

#[test]
fn target_picker_enter_applies_candidate_and_leaves_the_picker() {
    // Bare interactive `kuzushi` opens the target picker; Enter must wire
    // the chosen directory exactly like the `target <path>` verb and then
    // continue the first-run chain (never staying in the picker).
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target_candidates = vec![crate::app::TargetCandidate {
        path: dir.path().to_path_buf(),
        label: ".".to_string(),
        hint: "current directory",
    }];
    app.target_picker_cursor = 0;
    app.shell_view = ShellView::TargetPicker;

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    assert!(app.target.is_some(), "target applied from the picker");
    assert_ne!(app.shell_view, ShellView::TargetPicker);
}

#[test]
fn target_picker_esc_defers_to_home_without_a_target() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target_candidates = Vec::new();
    app.shell_view = ShellView::TargetPicker;

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view, ShellView::Home);
    assert!(app.target.is_none());
    assert!(app
        .log
        .iter()
        .any(|line| line.body.contains("browsing without a target")));
}

#[test]
fn scan_completion_raises_success_banner_when_operator_is_elsewhere() {
    // Ambient-progress story: background work must announce itself when it
    // lands while the operator is on another view — and stay quiet when
    // they're already watching the Activity feed.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.activity = Some(ActivitySession::new("r-scan"));
    app.shell_view = ShellView::Findings;
    app.apply_scan_finished("r-scan".to_string(), 3);
    let notice = app.advisory.notice.clone().expect("completion banner");
    assert_eq!(notice.severity, NoticeSeverity::Success);
    assert!(notice.message.contains("3 findings"), "{}", notice.message);
    assert!(notice.message.contains("`findings`"), "{}", notice.message);

    app.advisory.notice = None;
    app.activity = Some(ActivitySession::new("r-scan2"));
    app.shell_view = ShellView::Activity;
    app.apply_scan_finished("r-scan2".to_string(), 1);
    assert!(
        app.advisory.notice.is_none(),
        "no banner while watching the feed"
    );
}

#[test]
fn scene_view_is_never_a_trap() {
    // /scene used to eat h/j/k/l (camera orbit) even mid-word, making
    // `back` and `home` untypeable on the default 3D page, and Esc with a
    // half-typed prompt toggled clear/restore forever. The gallery must
    // always be exitable: Esc and q leave directly, and typing yields the
    // hotkeys to the prompt.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.handle_command(ShellCommand::Scene);
    app.sync_view_change();
    assert!(matches!(app.shell_view, ShellView::Scene(_)));
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!matches!(app.shell_view, ShellView::Scene(_)), "Esc exits");

    app.handle_command(ShellCommand::Scene);
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty()));
    assert!(!matches!(app.shell_view, ShellView::Scene(_)), "q exits");

    // Typing a command containing orbit keys must reach the prompt intact.
    app.handle_command(ShellCommand::Scene);
    for ch in "back".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
    }
    assert_eq!(app.input, "back", "orbit keys yield to a non-empty prompt");
}

#[test]
fn next_command_without_target_logs_guidance() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let view_before = app.shell_view.clone();
    app.handle_command(ShellCommand::Next);
    assert_eq!(app.shell_view, view_before);
    assert!(app
        .log
        .iter()
        .any(|line| line.body.contains("no active workspace target")));
}

fn make_finding(severity: Severity, fp: &str, title: &str) -> Finding {
    Finding {
        id: None,
        scan_id: None,
        fingerprint: fp.to_string(),
        rule_id: "test/rule".to_string(),
        title: title.to_string(),
        severity,
        file_path: "src/x.rs".to_string(),
        start_line: 1,
        end_line: None,
        message: String::new(),
        tool: "test".to_string(),
        actor_fingerprint: None,
        static_proof_state: None,
        triage: None,
        verification: None,
        created_at: String::new(),
        vuln_source: None,
        dedup_key: None,
        suppressed: false,
        snoozed_until: None,
        remediation: None,
        references: Vec::new(),
        evidence: Vec::new(),
    }
}

fn key_event_for_trigger(trigger: HotkeyTrigger) -> KeyEvent {
    let code = hotkey_trigger_code(trigger);
    KeyEvent::new(code, KeyModifiers::empty())
}

fn hotkey_trigger_code(trigger: HotkeyTrigger) -> KeyCode {
    if let HotkeyTrigger::Char(ch) = trigger {
        return KeyCode::Char(ch);
    }
    non_char_hotkey_code(trigger)
}

fn non_char_hotkey_code(trigger: HotkeyTrigger) -> KeyCode {
    const NON_CHAR_CODES: &[(HotkeyTrigger, KeyCode)] = &[
        (HotkeyTrigger::Enter, KeyCode::Enter),
        (HotkeyTrigger::Tab, KeyCode::Tab),
        (HotkeyTrigger::Esc, KeyCode::Esc),
        (HotkeyTrigger::PageUp, KeyCode::PageUp),
        (HotkeyTrigger::PageDown, KeyCode::PageDown),
        (HotkeyTrigger::Up, KeyCode::Up),
        (HotkeyTrigger::Down, KeyCode::Down),
    ];
    NON_CHAR_CODES
        .iter()
        .find_map(|(candidate, code)| (*candidate == trigger).then_some(*code))
        .unwrap_or(KeyCode::Null)
}

fn app_with_findings(count: usize) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.findings = (0..count)
        .map(|i| make_finding(Severity::High, &format!("fp-{i:04}"), "x"))
        .collect();
    app
}

fn app_with_module_run_scan(paused: bool) -> (ShellApp, ScanCancellation) {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    if paused {
        cancel.pause();
    }
    app.scan_cancel = Some(cancel.clone());
    app.scan = Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: if paused { "paused" } else { "running" }.to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::ModuleRun;
    (app, cancel)
}

#[test]
fn chain_alias_format_is_two_digit_zero_padded() {
    assert_eq!(format_chain_alias(0), "C-01");
    assert_eq!(format_chain_alias(8), "C-09");
    assert_eq!(format_chain_alias(9), "C-10");
}

#[test]
fn parse_chain_alias_round_trips() {
    for case in ["C-01", "c-01", "C-99", "C-1"] {
        let parsed = parse_chain_alias(case).expect("valid");
        assert!(format_chain_alias(parsed).len() == 4);
    }
    assert!(parse_chain_alias("F-0001").is_none());
    assert!(parse_chain_alias("garbage").is_none());
}

#[test]
fn sorted_chain_aliases_severity_then_id() {
    let chains = vec![
        ExploitChain {
            id: "z".to_string(),
            severity: ChainSeverity::Medium,
            title: "third".to_string(),
        },
        ExploitChain {
            id: "b".to_string(),
            severity: ChainSeverity::Critical,
            title: "first".to_string(),
        },
        ExploitChain {
            id: "a".to_string(),
            severity: ChainSeverity::Critical,
            title: "tied-but-earlier-id".to_string(),
        },
    ];
    let aliases = sorted_chain_aliases(&chains);
    assert_eq!(aliases[0].0, "C-01");
    assert_eq!(aliases[0].1.id, "a");
    assert_eq!(aliases[1].1.id, "b");
    assert_eq!(aliases[2].1.id, "z");
}

#[test]
fn alias_table_emits_both_chain_and_finding_rows() {
    let findings = vec![
        make_finding(Severity::High, "ffff1111", "ssrf"),
        make_finding(Severity::Critical, "aaaa2222", "sqli"),
    ];
    let chains = vec![ExploitChain {
        id: "chain-1".to_string(),
        severity: ChainSeverity::High,
        title: "auth bypass".to_string(),
    }];
    let table = format_alias_table(&findings, &chains, None);
    assert!(table.contains("C-01"));
    assert!(table.contains("F-0001"));
    assert!(table.contains("F-0002"));
    // critical sorts ahead of high
    let f1_pos = table.find("F-0001").unwrap();
    let f2_pos = table.find("F-0002").unwrap();
    assert!(f1_pos < f2_pos);
}

#[test]
fn alias_table_filters_by_prefix() {
    let findings = vec![make_finding(Severity::Medium, "abc12345", "x")];
    let chains = vec![ExploitChain {
        id: "c".to_string(),
        severity: ChainSeverity::Medium,
        title: "y".to_string(),
    }];
    let only_chains = format_alias_table(&findings, &chains, Some("C-"));
    assert!(only_chains.contains("C-01"));
    assert!(!only_chains.contains("F-0001"));
}

#[test]
fn alias_table_handles_empty() {
    let table = format_alias_table(&[], &[], None);
    assert!(table.contains("No aliases"));
}

#[test]
fn tune_set_writes_house_rules_and_reset_removes_them() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::Tune;
    app.submit_line("set \"focus on auth bypass\"");
    let path = temp.path().join(".kuzushi/house-rules/sast.md");
    assert!(path.exists());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "focus on auth bypass"
    );
    assert_eq!(
        app.read_house_rules().as_deref(),
        Some("focus on auth bypass")
    );
    app.submit_line("reset");
    assert!(!path.exists());
}

#[test]
fn quickstart_opens_dedicated_view_with_concise_log() {
    // Previously Quickstart switched to Help and dumped 8 log lines into a
    // 2-row transcript, so 6 of them were unreadable. Now it switches to
    // ShellView::Quickstart (which renders the full guide in the body
    // area) and only logs the single first-finding path entry.
    let mut app = ShellApp::new(V2Config::default(), None);
    let baseline_quickstart_lines = app
        .log
        .iter()
        .filter(|line| line.prefix == "quickstart")
        .count();
    app.handle_command(ShellCommand::Quickstart);
    assert_eq!(app.shell_view, ShellView::Quickstart);
    let new_lines: Vec<_> = app
        .log
        .iter()
        .filter(|line| line.prefix == "quickstart")
        .skip(baseline_quickstart_lines)
        .collect();
    assert_eq!(new_lines.len(), 1, "expected exactly one transcript line");
    assert!(new_lines[0].body.contains("scan . -> findings"));
}

#[test]
fn startup_logs_first_finding_path_for_bare_shell() {
    let app = ShellApp::new(V2Config::default(), None);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "startup" && line.body.contains("modules")));
    // P1-3: the first-finding hint is rendered in the catalog body,
    // not duplicated into the 2-row transcript. Confirm the helper
    // still produces the correct command so `next_action_line` has
    // something to render.
    assert_eq!(app.first_finding_scan_command(), "scan .");
    let hint = app.first_finding_hint();
    assert!(hint.contains("scan ."));
    assert!(hint.contains("findings"));
    assert!(
        !app.log.iter().any(|line| line.prefix == "first-run"),
        "transcript should no longer carry a first-run dup of the catalog hint"
    );
}

#[test]
fn startup_logs_active_target_first_finding_path() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let app = ShellApp::new(V2Config::default(), Some(&workspace));
    assert_eq!(app.first_finding_scan_command(), "scan");
    let hint = app.first_finding_hint();
    assert!(hint.contains("scan"));
    assert!(!hint.contains("scan ."));
    assert!(hint.contains("findings"));
}

#[test]
fn target_command_switches_target_directory() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let path_str = temp.path().to_string_lossy().to_string();
    app.handle_command(ShellCommand::Target(Some(path_str.clone())));
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    assert_eq!(app.target.as_deref(), Some(canonical.as_path()));
    // When called with no path, should report the current target.
    app.handle_command(ShellCommand::Target(None));
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "target" && line.body.contains("current target")));
}

#[test]
fn bracketed_paste_single_line_inserts_text_without_submit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::empty()));
    // Single-line pastes insert verbatim — Enter is NOT synthesized.
    app.handle_paste(" world");
    assert_eq!(app.input, "hi world");
    assert_eq!(app.cursor, app.input.chars().count());
    // Pressing Enter after a paste submits the line normally.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.input.is_empty());
}

#[test]
fn multi_line_paste_keeps_first_line_and_warns() {
    // Pasting 3 lines should not auto-submit each one — the shell is a
    // single-command-per-Enter prompt and submitting `rm` from a pasted
    // snippet would be catastrophic. Keep the first line, warn the user,
    // let them review and submit explicitly.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_paste("first\r\nsecond\nthird");
    assert_eq!(app.input, "first");
    assert_eq!(app.cursor, "first".chars().count());
    let advisory = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "paste")
        .expect("expected a paste advisory log line");
    assert!(advisory.body.contains("kept first line"));
    assert!(advisory.body.contains("dropped 2"));
}

#[test]
fn vi_cursor_navigates_findings_list() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.findings = vec![
        make_finding(Severity::High, "f1", "a"),
        make_finding(Severity::High, "f2", "b"),
        make_finding(Severity::High, "f3", "c"),
    ];

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 2, "j should clamp at last row");
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 0);
    app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 2);
}

#[test]
fn mouse_wheel_moves_findings_cursor_without_empty_underflow() {
    let mut app = app_with_findings(5);
    app.findings_cursor = 1;

    app.handle_mouse(crossterm::event::MouseEvent {
        kind: crossterm::event::MouseEventKind::ScrollDown,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.findings_cursor, 4);

    app.handle_mouse(crossterm::event::MouseEvent {
        kind: crossterm::event::MouseEventKind::ScrollUp,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.findings_cursor, 1);
}

#[test]
fn arrow_keys_move_cursor_within_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    for ch in "hello".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
    }
    assert_eq!(app.input, "hello");
    assert_eq!(app.cursor, 5);

    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::empty()));
    assert_eq!(app.cursor, 3);

    // Insert a char in the middle.
    app.handle_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::empty()));
    assert_eq!(app.input, "helXlo");
    assert_eq!(app.cursor, 4);

    app.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::empty()));
    assert_eq!(app.cursor, 0);
    app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::empty()));
    assert_eq!(app.cursor, app.input.chars().count());
}

#[test]
fn ctrl_w_deletes_word_left() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("scan ./path/to/foo");
    app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
    assert_eq!(app.input, "scan ./path/to/");
    app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
    assert_eq!(app.input, "scan ./path/");
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    assert_eq!(app.input, "");
    assert_eq!(app.cursor, 0);
}

#[test]
fn ctrl_a_e_b_f_navigate_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("abcd");
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
    assert_eq!(app.cursor, 0);
    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL));
    assert_eq!(app.cursor, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
    assert_eq!(app.cursor, 4);
    app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL));
    assert_eq!(app.cursor, 3);
}

#[test]
fn up_arrow_recalls_command_history() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.submit_line("/findings");
    app.submit_line("/modules");
    assert!(app.input.is_empty());

    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.input, "/modules");
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.input, "/findings");
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    assert_eq!(app.input, "/modules");
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    assert_eq!(app.input, "");
}

#[test]
fn page_keys_scroll_view_offset() {
    // Help has its own dedicated scroll field — PageDown/PageUp must
    // advance/retract it so `viewport_lines(..., app.help_scroll)` actually
    // shows the next page. Other views with their own scroll fields
    // (Tools, History, KnowledgeBase, Catalog when expanded) work the
    // same way; views without dedicated fields fall back to scroll_offset.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;
    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.help_scroll, 10);
    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.help_scroll, 20);
    app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty()));
    assert_eq!(app.help_scroll, 10);

    // Views without a dedicated scroll field still use scroll_offset.
    app.shell_view = ShellView::Tune;
    app.scroll_offset = 0;
    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.scroll_offset, 10);
}

#[test]
fn changing_view_resets_scroll_offset() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;
    app.scroll_offset = 25;
    app.sync_view_change();
    // First sync after construction: prev_shell_view starts None, so scroll resets.
    assert_eq!(app.scroll_offset, 0);
    // Move scroll, switch view, sync again — scroll resets again.
    app.scroll_offset = 12;
    app.shell_view = ShellView::Tools;
    app.sync_view_change();
    assert_eq!(app.scroll_offset, 0);
}

#[test]
fn completion_preview_shows_only_when_cursor_at_end() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("/he");
    // Cursor at end → preview returns the tail "lp".
    let preview = app.completion_preview();
    assert_eq!(preview.as_deref(), Some("lp"));

    // Move cursor mid-line → preview suppressed (would render in the wrong place).
    app.cursor = 1;
    assert!(app.completion_preview().is_none());

    // Empty input → no preview (cold-start prompt should stay clean).
    app.clear_input();
    assert!(app.completion_preview().is_none());

    // Already a complete word with no further suffix → no preview.
    app.set_input("/help");
    assert!(app.completion_preview().is_none());
}

#[test]
fn vi_keys_scroll_help_view() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.scroll_offset, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    assert_eq!(app.scroll_offset, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()));
    assert_eq!(app.scroll_offset, u16::MAX);
    app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()));
    assert_eq!(app.scroll_offset, 0);
}

#[test]
fn tick_advances_spinner_only_when_running() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let initial_phase = app.spinner_phase;
    // Idle: tick() returns false and does not advance the spinner.
    let changed = app.tick();
    assert!(!changed);
    assert_eq!(app.spinner_phase, initial_phase);
    // Mark a scan as running and tick — the spinner advances and tick reports change.
    app.scan = Some(crate::app::ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    // Force the spinner to advance even though no real time has passed.
    app.last_spinner_advance = Some(Instant::now() - Duration::from_millis(200));
    let changed = app.tick();
    assert!(changed);
    assert_eq!(app.spinner_phase, initial_phase.wrapping_add(1));
}

#[test]
fn pgdown_pgup_paginate_findings_cursor() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.findings = (0..25)
        .map(|i| make_finding(Severity::High, &format!("fp-{i}"), "x"))
        .collect();
    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 10);
    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 20);
    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 24);
    app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty()));
    assert_eq!(app.findings_cursor, 14);
}

#[test]
fn viewport_enter_opens_cursor_finding_from_visible_list() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.findings = vec![
        make_finding(Severity::High, "fp-0000", "first"),
        make_finding(Severity::High, "fp-0001", "second"),
    ];
    app.findings_cursor = 1;

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    assert_eq!(app.shell_view, ShellView::Finding);
    assert_eq!(
        app.selected_finding
            .as_ref()
            .map(|finding| finding.title.as_str()),
        Some("second")
    );
}

#[test]
fn keybind_advertised_findings_hotkeys_drive_state_transitions() {
    let app = app_with_findings(25);
    let advertised = app.view_keybindings();
    assert!(advertised
        .iter()
        .any(|binding| binding.hint.contains("j/k")));
    assert!(advertised.iter().any(|binding| binding.hint == "PgUp/PgDn"));
    assert!(advertised.iter().any(|binding| binding.hint == "Enter"));

    for binding in advertised {
        let mut app = app_with_findings(25);
        match binding.action {
            ViewHotkeyAction::FindingsNext => {
                app.findings_cursor = 0;
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.findings_cursor, 1);
            }
            ViewHotkeyAction::FindingsPrevious => {
                app.findings_cursor = 1;
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.findings_cursor, 0);
            }
            ViewHotkeyAction::FindingsFirst => {
                app.findings_cursor = 7;
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.findings_cursor, 0);
            }
            ViewHotkeyAction::FindingsLast => {
                app.findings_cursor = 7;
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.findings_cursor, 24);
            }
            ViewHotkeyAction::FindingsPageDown => {
                app.findings_cursor = 0;
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.findings_cursor, 10);
            }
            ViewHotkeyAction::FindingsPageUp => {
                app.findings_cursor = 10;
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.findings_cursor, 0);
            }
            ViewHotkeyAction::FindingsOpen => {
                app.findings_cursor = 2;
                let expected = app.findings[2].fingerprint.clone();
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view, ShellView::Finding);
                assert_eq!(
                    app.selected_finding
                        .as_ref()
                        .map(|finding| finding.fingerprint.as_str()),
                    Some(expected.as_str())
                );
            }
            ViewHotkeyAction::Back => {
                let mut app = app_with_findings(25);
                app.nav_history.push(ShellView::Catalog);
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view, ShellView::Catalog);
            }
            other => panic!("unexpected findings hotkey action: {other:?}"),
        }
    }
}

#[test]
fn prompt_set_writes_override_file_and_reset_removes_it() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::PromptsEditor;

    app.submit_line("set triage \"focus on auth bypass\"");
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    assert!(path.exists());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "focus on auth bypass"
    );

    app.submit_line("reset triage");
    assert!(!path.exists());
}

#[test]
fn bare_verbs_only_intercepted_in_prompts_editor_view() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.focused_module = Some("sast".to_string());
    // NOT in prompts editor — should fall through to normal parser, which treats
    // unknown bare verbs as Unknown (not a prompt write).
    app.shell_view = ShellView::Catalog;
    app.submit_line("set triage \"abc\"");
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    assert!(!path.exists());
}

#[test]
fn ctrl_o_toggles_story_overlay_back_to_origin() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Findings;
    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view, ShellView::Story);
    assert_eq!(app.story_return_view, Some(ShellView::Findings));
    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view, ShellView::Findings);
    assert!(app.story_return_view.is_none());
}

#[test]
fn scan_cancellation_pause_and_resume_round_trip() {
    let cancel = ScanCancellation::default();
    assert!(!cancel.is_paused());
    cancel.pause();
    assert!(cancel.is_paused());
    cancel.resume();
    assert!(!cancel.is_paused());
}

#[test]
fn cancel_clears_pause_so_workers_observe_cancellation() {
    let cancel = ScanCancellation::default();
    cancel.pause();
    cancel.cancel();
    assert!(cancel.is_cancelled());
    assert!(!cancel.is_paused());
}

#[test]
fn pause_command_during_active_scan_pauses_cancellation() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.scan_cancel = Some(cancel.clone());
    app.scan = Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.handle_command(ShellCommand::Pause);
    assert!(cancel.is_paused());
    assert!(app.is_scan_paused());
    assert_eq!(
        app.scan.as_ref().map(|scan| scan.stage.as_str()),
        Some("paused")
    );
}

#[test]
fn resume_command_resumes_paused_scan() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    cancel.pause();
    app.scan_cancel = Some(cancel.clone());
    app.scan = Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "paused".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.handle_command(ShellCommand::Resume(None));
    assert!(!cancel.is_paused());
    assert_eq!(
        app.scan.as_ref().map(|scan| scan.stage.as_str()),
        Some("running")
    );
}

#[test]
fn module_run_p_and_r_keys_pause_resume() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.scan_cancel = Some(cancel.clone());
    app.scan = Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::ModuleRun;
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(cancel.is_paused());
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()));
    assert!(!cancel.is_paused());
}

#[test]
fn keybind_advertised_module_run_hotkeys_drive_state_transitions() {
    let (app, _) = app_with_module_run_scan(false);
    let advertised = app.view_keybindings();
    assert!(advertised.iter().any(|binding| binding.hint == "1..4"));
    assert!(advertised.iter().any(|binding| binding.hint == "p"));
    assert!(!advertised.iter().any(|binding| binding.hint == "r"));

    for binding in advertised {
        match binding.action {
            ViewHotkeyAction::ActorDetail(index) => {
                let (mut app, _) = app_with_module_run_scan(false);
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view, ShellView::ActorDetail(index));
            }
            ViewHotkeyAction::PauseScan => {
                let (mut app, cancel) = app_with_module_run_scan(false);
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert!(cancel.is_paused());
                assert_eq!(
                    app.scan.as_ref().map(|scan| scan.stage.as_str()),
                    Some("paused")
                );
            }
            ViewHotkeyAction::ViewScrollUp
            | ViewHotkeyAction::ViewScrollDown
            | ViewHotkeyAction::ViewScrollTop
            | ViewHotkeyAction::ViewScrollBottom
            | ViewHotkeyAction::ViewPageUp
            | ViewHotkeyAction::ViewPageDown => {
                // Shared scroll base — exercise to confirm the key is consumed
                // without panicking on the ModuleRun view.
                let (mut app, _) = app_with_module_run_scan(false);
                app.handle_key(key_event_for_trigger(binding.trigger));
            }
            ViewHotkeyAction::Back => {
                let (mut app, _) = app_with_module_run_scan(false);
                app.nav_history.push(ShellView::Catalog);
                app.handle_key(key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view, ShellView::Catalog);
            }
            other => panic!("unexpected active module-run hotkey action: {other:?}"),
        }
    }

    let (paused_app, _) = app_with_module_run_scan(true);
    let paused_advertised = paused_app.view_keybindings();
    assert!(paused_advertised
        .iter()
        .any(|binding| binding.hint == "1..4"));
    assert!(paused_advertised.iter().any(|binding| binding.hint == "r"));
    assert!(!paused_advertised.iter().any(|binding| binding.hint == "p"));

    for binding in paused_advertised
        .into_iter()
        .filter(|binding| matches!(binding.action, ViewHotkeyAction::ResumeScan))
    {
        let (mut app, cancel) = app_with_module_run_scan(true);
        app.handle_key(key_event_for_trigger(binding.trigger));
        assert!(!cancel.is_paused());
        assert_eq!(
            app.scan.as_ref().map(|scan| scan.stage.as_str()),
            Some("running")
        );
    }
}

#[test]
fn scrollable_views_advertise_scroll_and_back_hints() {
    let scrollable = [
        ShellView::Help,
        ShellView::Tools,
        ShellView::History,
        ShellView::Workspace,
        ShellView::KnowledgeBase,
        ShellView::Context,
        ShellView::Story,
    ];
    for view in scrollable {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = view.clone();
        let advertised = app.view_keybindings();
        assert!(
            advertised.iter().any(|binding| binding.hint == "j/k/g/G"),
            "{view:?} should advertise scroll keys"
        );
        assert!(
            advertised
                .iter()
                .any(|binding| binding.action == ViewHotkeyAction::Back),
            "{view:?} should advertise a back binding"
        );
    }
}

#[test]
fn esc_goes_back_to_previous_view_when_input_empty() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Tools;
    app.nav_history.push(ShellView::Catalog);

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view, ShellView::Catalog);
}

#[test]
fn esc_clears_draft_instead_of_going_back_when_typing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Tools;
    app.nav_history.push(ShellView::Catalog);
    app.input = "scan".to_string();
    app.cursor = app.input.chars().count();

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view, ShellView::Tools, "view must not change");
    assert!(app.input.is_empty(), "draft should be cleared");
    assert_eq!(app.last_cleared_input.as_deref(), Some("scan"));
}

#[test]
fn esc_restores_stashed_draft_instead_of_going_back() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Tools;
    app.nav_history.push(ShellView::Catalog);
    app.last_cleared_input = Some("scan".to_string());

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view, ShellView::Tools, "view must not change");
    assert_eq!(app.input, "scan", "stashed draft should be restored");
}

#[test]
fn activity_view_does_not_offer_back_binding() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Activity;
    assert!(
        !app.view_keybindings()
            .iter()
            .any(|binding| binding.action == ViewHotkeyAction::Back),
        "Activity owns Esc (cancel run), so it must not bind Esc to back"
    );
}

#[test]
fn picker_views_are_not_recorded_in_nav_history() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ModelPicker;
    app.sync_view_change();
    app.shell_view = ShellView::Catalog;
    app.sync_view_change();

    assert!(
        !app.nav_history.contains(&ShellView::ModelPicker),
        "onboarding pickers must never enter the back stack"
    );
}

#[test]
fn parse_threat_patch_extracts_summary_and_patch() {
    let body = r#"{"summary":"add admin trust zone","patch":{"trustZones":{"admin":"isolated"}},"unsupported":[]}"#;
    let patch = parse_threat_patch_json("regen", body).unwrap();
    assert_eq!(patch.summary, "add admin trust zone");
    assert_eq!(
        patch
            .patch
            .pointer("/trustZones/admin")
            .and_then(|v| v.as_str()),
        Some("isolated")
    );
}

#[test]
fn merge_json_deep_merges_objects_and_handles_null_deletion() {
    let mut target = serde_json::json!({"trustZones":{"admin":"trusted","public":"untrusted"}});
    let patch = serde_json::json!({"trustZones":{"admin":"isolated","db":"private","public":null}});
    merge_json(&mut target, &patch);
    assert_eq!(
        target,
        serde_json::json!({"trustZones":{"admin":"isolated","db":"private"}})
    );
}

#[test]
fn apply_pending_threat_patch_writes_to_disk() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().to_path_buf();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(target.clone());
    // Seed an existing model.
    save_persistent_threat_model(
        &target,
        &serde_json::json!({"trustZones":{"admin":"trusted"}}),
        true,
    )
    .unwrap();
    app.set_pending_threat_patch(ThreatPatch {
        goal: "g".to_string(),
        summary: "s".to_string(),
        patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
        unsupported: vec![],
    });
    app.apply_pending_threat_patch();
    let written = load_persistent_threat_model(&target).unwrap();
    assert_eq!(
        written
            .pointer("/trustZones/admin")
            .and_then(|v| v.as_str()),
        Some("isolated")
    );
    assert!(app.pending_threat_patch.is_none());
}

#[test]
fn discard_threat_patch_clears_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_threat_patch(ThreatPatch {
        goal: "g".to_string(),
        summary: "s".to_string(),
        patch: serde_json::json!({}),
        unsupported: vec![],
    });
    app.discard_pending_threat_patch();
    assert!(app.pending_threat_patch.is_none());
}

#[test]
fn parse_plan_json_handles_well_formed_proposal() {
    let body = r#"{
            "summary": "lower SAST noise",
            "changes": [
                {"kind": "set_option", "tool": "sast:scan", "global": false, "name": "triage", "value": true},
                {"kind": "ask", "question": "any auth bypass risks?"},
                {"kind": "note", "text": "remember to re-baseline"}
            ],
            "unsupported": ["cannot toggle compiler hardening"]
        }"#;
    let plan = parse_plan_json("reduce noise", body).unwrap();
    assert_eq!(plan.goal, "reduce noise");
    assert_eq!(plan.summary, "lower SAST noise");
    assert_eq!(plan.changes.len(), 3);
    assert_eq!(plan.unsupported, vec!["cannot toggle compiler hardening"]);
}

#[test]
fn parse_plan_json_skips_unknown_change_kinds() {
    let body = r#"{"summary":"x","changes":[{"kind":"explode","name":"x"}],"unsupported":[]}"#;
    let plan = parse_plan_json("x", body).unwrap();
    assert!(plan.changes.is_empty());
}

#[test]
fn parse_plan_json_strips_surrounding_prose() {
    let body =
        "Here is the plan:\n```\n{\"summary\":\"x\",\"changes\":[],\"unsupported\":[]}\n```\n";
    let plan = parse_plan_json("x", body).unwrap();
    assert_eq!(plan.summary, "x");
}

#[test]
fn pending_plan_y_key_applies() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_plan(PlanProposal {
        goal: "g".to_string(),
        summary: "s".to_string(),
        changes: vec![PlanChange::Note {
            text: "noted".to_string(),
        }],
        unsupported: vec![],
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::empty()));
    assert!(app.pending_plan.is_none());
    assert!(app.log.iter().any(|line| line.body.contains("noted")));
}

#[test]
fn pending_plan_n_key_discards() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_plan(PlanProposal {
        goal: "g".to_string(),
        summary: "s".to_string(),
        changes: vec![],
        unsupported: vec![],
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()));
    assert!(app.pending_plan.is_none());
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "plan" && line.body.contains("discarded")));
}

#[test]
fn budget_halt_c_continues_a_aborts() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_budget_usd = Some(0.05);
    app.record_cost(0.10);
    assert!(app.is_budget_halted());

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()));
    assert!(!app.is_budget_halted(), "c should clear the halt");

    app.session_cost_usd = 0.30;
    app.session_budget_usd = Some(0.20);
    app.record_cost(0.0);
    // Force re-trigger by lowering cap and recording zero (helper rechecks).
    app.advisory.budget_halt = Some(BudgetHalt {
        limit_usd: 0.20,
        spent_usd: 0.30,
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()));
    assert!(!app.is_budget_halted(), "a should clear the halt");
}

#[test]
fn ctrl_c_during_active_scan_requests_abort_without_arming() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(ScanPanelState {
        run_id: Some("run-x".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(!app.should_quit);
    assert!(!app.ctrl_c_armed(), "scan-cancel path must not arm exit");
    assert!(app.scan.as_ref().is_some_and(|scan| scan.abort_requested));
}

#[test]
fn second_ctrl_c_after_scan_abort_request_arms_exit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(ScanPanelState {
        run_id: Some("run-x".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert!(!app.should_quit);
    assert!(app.ctrl_c_armed());
}

#[test]
fn ctrl_c_during_agent_chat_requests_abort_without_claiming_kill() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::AgentChat;
    app.agent_chat = Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert!(!app.should_quit);
    assert!(!app.ctrl_c_armed());
    assert!(app
        .agent_chat
        .as_ref()
        .is_some_and(|agent| agent.abort_requested));
    assert!(app.log.iter().any(|line| {
        line.prefix == "agent"
            && line.body.contains("abort requested")
            && line.body.contains("not confirmed")
    }));
}

#[test]
fn agent_response_after_abort_request_is_ignored() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.agent_chat = Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: true,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });

    app.apply_agent_event(AgentEvent::Answered {
        text: "late answer".to_string(),
        audit: test_agent_audit(),
    });

    let agent = app.agent_chat.as_ref().unwrap();
    assert!(!agent.running);
    assert!(!agent.abort_requested);
    assert!(agent.answer.is_none());
    assert!(agent
        .error
        .as_ref()
        .is_some_and(|error| error.contains("ignored")));
    assert!(!app.log.iter().any(|line| line.body == "late answer"));
}

#[test]
fn agent_answer_event_records_llm_audit_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.agent_chat = Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: Some("agent-answer".to_string()),
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });

    app.apply_agent_event(AgentEvent::Answered {
        text: "inspect report.md".to_string(),
        audit: test_agent_audit(),
    });

    let summary = load_run_summary(tmp.path(), "agent-answer").unwrap();
    assert_eq!(summary.llm_calls.len(), 1);
    assert_eq!(summary.llm_calls[0].model, "openai:gpt-test");
    assert_eq!(summary.llm_calls[0].provider, "openai");
    assert!(summary.llm_calls[0].prompt_hash.starts_with("fnv1a64:"));
    assert_eq!(summary.llm_calls[0].cost_usd, Some(0.012));
    let events =
        fs::read_to_string(kuzushi_core::run_dir(tmp.path(), "agent-answer").join("events.jsonl"))
            .unwrap();
    assert!(events.contains(r#""status":"completed""#));
    assert!(events.contains(r#""tool":"agent:ask""#));
}

#[test]
fn agent_failure_event_records_bounded_failure_handoff() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.agent_chat = Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: Some("agent-failed".to_string()),
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });

    app.apply_agent_event(AgentEvent::Failed {
        error: "bridge denied the model request".to_string(),
        audit: test_agent_audit(),
    });

    let failures = load_run_failures(tmp.path(), "agent-failed").unwrap();
    assert_eq!(failures.status, "failed");
    let failure = failures.failures.first().unwrap();
    assert_eq!(failure.tool, "agent:ask");
    assert!(failure
        .agent_thread_context
        .fallback_prompt
        .contains("bridge denied"));
    let events =
        fs::read_to_string(kuzushi_core::run_dir(tmp.path(), "agent-failed").join("events.jsonl"))
            .unwrap();
    assert!(events.contains(r#""status":"failed""#));
    assert!(events.contains(r#""tool":"agent:ask""#));
}

fn test_agent_audit() -> AgentCallAudit {
    AgentCallAudit::for_prompt("openai:gpt-test", ASK_SYSTEM_PROMPT, "what changed?")
        .with_cost_usd(0.012)
}

#[test]
fn scan_failure_event_records_bounded_failure_handoff() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.scan = Some(ScanPanelState {
        run_id: Some("scan-failed".to_string()),
        target: tmp.path().to_path_buf(),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    app.apply_scan_failed("semgrep binary missing".to_string());

    let failures = load_run_failures(tmp.path(), "scan-failed").unwrap();
    assert_eq!(failures.status, "failed");
    let failure = failures.failures.first().unwrap();
    assert_eq!(failure.tool, "sast:scan");
    assert!(failure
        .agent_thread_context
        .fallback_prompt
        .contains("semgrep binary missing"));
    let events =
        fs::read_to_string(kuzushi_core::run_dir(tmp.path(), "scan-failed").join("events.jsonl"))
            .unwrap();
    assert!(events.contains(r#""status":"failed""#));
    assert!(events.contains(r#""tool":"sast:scan""#));
}

#[test]
fn ctrl_c_during_plan_and_threat_workers_requests_honest_abort() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.planner_running = true;
    app.threat_worker_running = true;

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert!(app.plan_abort_requested);
    assert!(app.threat_abort_requested);
    assert!(!app.should_quit);
    assert!(app.log.iter().any(|line| {
        line.prefix == "plan"
            && line.body.contains("abort requested")
            && line.body.contains("not confirmed")
    }));
    assert!(app.log.iter().any(|line| {
        line.prefix == "threats"
            && line.body.contains("abort requested")
            && line.body.contains("not confirmed")
    }));
}

#[test]
fn ctrl_c_during_background_tool_requests_honest_abort_without_exiting() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tool_running = Some("context:build".to_string());

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert!(app.tool_abort_requested);
    assert!(!app.ctrl_c_armed());
    assert!(!app.should_quit);
    assert!(app.log.iter().any(|line| {
        line.prefix == "tool"
            && line.body.contains("context:build abort requested")
            && line.body.contains("not confirmed")
    }));
}

#[test]
fn background_tool_failure_clears_running_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tool_running = Some("randori:pasta".to_string());
    app.tool_abort_requested = true;

    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "randori:pasta".to_string(),
        error: "randori:pasta could not satisfy structured JSON contract `ThreatModelDocument`"
            .to_string(),
    });

    assert_eq!(app.running_tool_name(), None);
    assert!(!app.tool_abort_requested());
    assert!(app.log.iter().any(|line| {
        line.prefix == "error"
            && line
                .body
                .contains("randori:pasta ended after abort request")
            && line.body.contains("ThreatModelDocument")
    }));
}

#[test]
fn tool_failure_marks_activity_dag_row_failing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.activity = Some(ActivitySession::new("run-1"));
    app.tool_running = Some("cpg:build".to_string());
    // Seed the row as the start step would, leaving it Active/running.
    app.activity.as_mut().unwrap().apply_step(
        kuzushi_core::RunTraceStep::new(0, "tool", "cpg:build start")
            .with_module_id("cpg")
            .with_verb("build"),
    );
    assert_eq!(
        app.activity.as_ref().unwrap().tasks["cpg:build"].state,
        crate::DagTaskState::Active
    );

    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "cpg:build".to_string(),
        error: "joern-parse exited with status Some(1): astgen not found".to_string(),
    });

    let row = &app.activity.as_ref().unwrap().tasks["cpg:build"];
    assert_eq!(
        row.state,
        crate::DagTaskState::Failing,
        "the DAG row must reflect the failure, not keep running"
    );
    assert!(row.completed_at.is_some(), "failed row should be terminal");
}

#[test]
fn background_tool_failure_logs_failure_handoff_context() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.tool_run_id = Some("tool-failed".to_string());
    app.tool_running = Some("semgrep:scan".to_string());

    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "semgrep:scan".to_string(),
        error: "semgrep binary missing".to_string(),
    });

    let result_log = app
        .log
        .iter()
        .find(|line| line.prefix == "result")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(result_log.contains("\"status\": \"failed\""));
    assert!(result_log.contains("\"fallback_context\""));
    assert!(result_log.contains("\"failedStage\": \"semgrep:scan\""));
    assert!(result_log.contains("semgrep binary missing"));
    assert!(app.log.iter().any(|line| {
        line.prefix == "failure-context"
            && line.body.contains("stage: semgrep:scan")
            && line.body.contains("cause: semgrep binary missing")
            && line.body.contains("artifact-review-only")
            && line.body.contains("missing:")
            && line.body.contains("recovery:")
            && line.body.contains("forbidden claims")
            && line.body.contains("empirical proof claim")
            && !line.body.contains("validated")
    }));
    assert!(app
        .agent_chat
        .as_ref()
        .and_then(|agent| agent.failure_context.as_ref())
        .is_some_and(|context| context.failed_stage == "semgrep:scan"));
    assert!(app
        .agent_chat
        .as_ref()
        .and_then(|agent| agent.pending_failure_context.as_ref())
        .is_some_and(|context| context.failed_stage == "semgrep:scan"));
}

#[test]
fn background_tool_partial_result_logs_fallback_context_in_result() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.tool_run_id = Some("tool-partial".to_string());
    app.tool_running = Some("codeql:scan".to_string());

    app.apply_tool_event(ToolEvent::Finished {
        tool_name: "codeql:scan".to_string(),
        result: serde_json::json!({
            "ok": false,
            "status": "partial",
            "summary": "CodeQL scanner was unavailable",
            "errors": ["codeql binary missing"],
            "warnings": [],
            "artifacts": []
        }),
    });

    let result_log = app
        .log
        .iter()
        .rev()
        .find(|line| line.prefix == "result")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(result_log.contains("fallback_context"));
    assert!(result_log.contains("\"failedStage\": \"codeql:scan\""));
    assert!(app
        .agent_chat
        .as_ref()
        .and_then(|agent| agent.pending_failure_context.as_ref())
        .is_some_and(|context| context.failed_stage == "codeql:scan"));
}

#[test]
fn failure_handoff_command_opens_dedicated_view() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::FailureHandoff);

    assert_eq!(app.shell_view, ShellView::FailureHandoff);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "handoff" && line.body.contains("no failure handoff")));
}

#[test]
fn recommend_command_opens_artifact_backed_view() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.handle_command(ShellCommand::Recommend);

    assert_eq!(app.shell_view, ShellView::Recommend);
    assert!(app
        .log
        .iter()
        .any(|line| line.prefix == "recommend" && line.body.contains("latest")));
}

#[test]
fn actor_detail_filter_cycle_and_reset() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ActorDetail(1);

    assert_eq!(app.actor_detail_filter, ActorDetailFilter::All);
    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()));
    assert_eq!(app.actor_detail_filter, ActorDetailFilter::Findings);
    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()));
    assert_eq!(app.actor_detail_filter, ActorDetailFilter::Errors);
    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()));
    assert_eq!(app.actor_detail_filter, ActorDetailFilter::Tools);
    app.handle_key(KeyEvent::new(KeyCode::Char('0'), KeyModifiers::empty()));
    assert_eq!(app.actor_detail_filter, ActorDetailFilter::All);
}

#[test]
fn prompts_editor_cursor_and_action_shortcuts() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::PromptsEditor;

    assert_eq!(app.current_prompt_verb_name(), Some("scan"));
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.current_prompt_verb_name(), Some("triage"));
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    assert_eq!(app.current_prompt_verb_name(), Some("verify"));
    let log_before = app.log.len();
    app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::empty()));
    assert!(app.log.len() > log_before);
}

#[test]
fn tune_view_cursor_and_activate() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Tune;

    assert_eq!(app.tune_cursor, 0);
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    assert_eq!(app.tune_cursor, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.tune_cursor, 2);
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.current_tune_action(), Some(TuneAction::EditHouseRules));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.input, "set \"\"");
    assert_eq!(app.cursor, app.input.chars().count() - 1);
}

#[test]
fn confirm_gate_detects_network_egress_for_sandbox_run_with_url() {
    let allow = std::collections::BTreeSet::new();
    let req = confirm_gate_for_tool(
        "sandbox:run",
        &serde_json::json!({"target": "https://refund.acme/api"}),
        &allow,
    )
    .expect("network egress gate");
    assert_eq!(req.kind, ConfirmKind::NetworkEgress);
    assert_eq!(req.tool, "sandbox:run");
    assert_eq!(req.target, "https://refund.acme/api");
}

#[test]
fn confirm_gate_skips_network_when_allowlisted() {
    let mut allow = std::collections::BTreeSet::new();
    allow.insert("sandbox:run https://refund.acme/api".to_string());
    assert!(confirm_gate_for_tool(
        "sandbox:run",
        &serde_json::json!({"target": "https://refund.acme/api"}),
        &allow,
    )
    .is_none());
}

#[test]
fn confirm_gate_detects_fs_write_outside_kuzushi() {
    let allow = std::collections::BTreeSet::new();
    let req = confirm_gate_for_tool(
        "fs:write",
        &serde_json::json!({"path": "apps/web/agents/concierge.ts"}),
        &allow,
    )
    .expect("fs:write gate");
    assert_eq!(req.kind, ConfirmKind::FsWriteOutsideKuzushi);

    // .kuzushi/ paths bypass the gate.
    assert!(confirm_gate_for_tool(
        "fs:write",
        &serde_json::json!({"path": ui_run_artifact_relative_path("r-1", "patch.diff")}),
        &allow,
    )
    .is_none());

    // A `..` traversal that escapes .kuzushi/ must still be confirmed, even
    // though the string starts with `.kuzushi/`.
    let escape = confirm_gate_for_tool(
        "fs:write",
        &serde_json::json!({"path": ".kuzushi/../../etc/passwd"}),
        &allow,
    )
    .expect("traversal escaping .kuzushi/ must be confirmed");
    assert_eq!(escape.kind, ConfirmKind::FsWriteOutsideKuzushi);
}

#[test]
fn move_model_selection_only_visits_visible_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    // The Config view hides the non-primary OpenAI row, so navigation must never
    // park the selection on a hidden index (which the renderer would collapse to
    // the first visible row, desyncing the highlight from the Enter target).
    let visible = super::settings::visible_model_choice_indexes(app.config.model.as_deref());
    app.selected_model_index = visible[0];
    for _ in 0..(visible.len() * 2 + 1) {
        app.move_model_selection(1);
        assert!(
            visible.contains(&app.selected_model_index),
            "forward step escaped visible set {visible:?}: {}",
            app.selected_model_index
        );
    }
    for _ in 0..(visible.len() * 2 + 1) {
        app.move_model_selection(-1);
        assert!(
            visible.contains(&app.selected_model_index),
            "back step escaped visible set {visible:?}: {}",
            app.selected_model_index
        );
    }
}

#[test]
fn confirm_gate_destructive_verb_unconditional_even_when_allowlisted() {
    let mut allow = std::collections::BTreeSet::new();
    // Even an explicit entry shouldn't bypass destructive verb gates.
    allow.insert("shell:run rm -rf .git".to_string());
    let req = confirm_gate_for_tool(
        "shell:run",
        &serde_json::json!({"cmd": "rm -rf .git"}),
        &allow,
    )
    .expect("destructive verb gate");
    assert_eq!(req.kind, ConfirmKind::DestructiveVerb);
}

#[test]
fn confirm_resolve_remember_writes_session_allowlist() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.pending_confirm = Some(PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "https://refund.acme/api".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    app.resolve_confirm(true, true);
    assert!(app
        .confirm_allowlist
        .contains("sandbox:run https://refund.acme/api"));
    assert!(app.advisory.pending_confirm.is_none());
}

#[test]
fn append_trace_step_writes_jsonl_under_target() {
    // The trace writer should land at
    // <target>/.kuzushi/runs/<runId>/trace.jsonl with one JSON
    // object per line.
    let tmp = tempfile::tempdir().unwrap();
    append_trace_step(
        Some(tmp.path()),
        "agent-42",
        1,
        "plan",
        "ask demo question",
        Some(400),
        None,
    );
    append_trace_step(
        Some(tmp.path()),
        "agent-42",
        2,
        "llm",
        "answer (24 chars)",
        Some(1200),
        Some(0.012),
    );
    let path = run_dir(tmp.path(), "agent-42").join("trace.jsonl");
    let body = std::fs::read_to_string(&path).expect("trace.jsonl");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["n"], 1);
    assert_eq!(first["kind"], "plan");
    assert_eq!(first["label"], "ask demo question");
    assert_eq!(first["latency_ms"], 400);
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(second["kind"], "llm");
    assert_eq!(second["cost_usd"], 0.012);
}

#[test]
fn append_trace_step_no_op_when_target_is_none() {
    // Sanity: passing None must not pollute the cwd.  The function
    // returns silently.
    append_trace_step(None, "agent-x", 1, "plan", "no target", None, None);
}

#[test]
fn write_run_summary_writes_canonical_run_metadata_under_target() {
    let tmp = tempfile::tempdir().unwrap();
    write_run_summary(Some(tmp.path()), "r-1", "complete", Some(11), "/tmp/demo");
    for leaf in ["run.json", "summary.json"] {
        let body = std::fs::read_to_string(run_dir(tmp.path(), "r-1").join(leaf))
            .unwrap_or_else(|_| panic!("{leaf}"));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["status"], "completed");
        assert_eq!(parsed["findings"], 11);
        assert_eq!(parsed["target"], "/tmp/demo");
    }
}

#[test]
fn append_run_status_event_records_tool_lifecycle_event() {
    let tmp = tempfile::tempdir().unwrap();
    write_run_summary(Some(tmp.path()), "r-event", "running", None, "/tmp/demo");
    append_run_status_event(
        Some(tmp.path()),
        "r-event",
        "sast:scan",
        "complete",
        "sast:scan completed",
    );

    let body = fs::read_to_string(run_dir(tmp.path(), "r-event").join("events.jsonl")).unwrap();
    let event: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(event["kind"], "tool");
    assert_eq!(event["status"], "completed");
    assert_eq!(event["tool"], "sast:scan");
    assert_eq!(event["message"], "sast:scan completed");
}

#[test]
fn write_run_failure_handoff_records_bounded_context() {
    let tmp = tempfile::tempdir().unwrap();
    write_run_summary(Some(tmp.path()), "r-failed", "failed", None, "/tmp/demo");
    write_run_failure_handoff(
        Some(tmp.path()),
        "r-failed",
        "sast:scan",
        "failed",
        "semgrep binary missing",
    );

    let failures = load_run_failures(tmp.path(), "r-failed").unwrap();
    assert_eq!(failures.status, "failed");
    let failure = failures.failures.first().unwrap();
    assert_eq!(failure.tool, "sast:scan");
    assert_eq!(failure.agent_thread_context.failed_stage, "sast:scan");
    assert!(failure
        .agent_thread_context
        .fallback_prompt
        .contains("semgrep binary missing"));
    assert!(failure
        .agent_thread_context
        .claims_forbidden
        .iter()
        .any(|claim| claim.contains("proof claim")));
}

#[test]
fn cache_tool_snapshot_populates_pending_patch_for_patch_run() {
    // patch:run / patch:finding tools produce a structured payload
    // the operator must approve.  Verify cache_tool_snapshot parses
    // the payload, sets `pending_patch`, and navigates to the Patch
    // view automatically.
    let mut app = ShellApp::new(V2Config::default(), None);
    let result = serde_json::json!({
        "data": {
            "alias": "F-0001",
            "rationale": "switch to sqlx::query!() macro",
            "side_effect": "closes F-0014",
            "diff": "--- a/x.rs\n+++ b/x.rs\n@@ -1 +1 @@\n-old\n+new\n",
            "tests": [
                {"name": "rejects_sqli", "blurb": "1 OR 1=1 → BadId"},
                {"name": "happy_path", "blurb": "valid uuid"},
            ],
            "guardrail": "approval.patches = human-required",
            "staged_at": ui_run_artifact_relative_path("r-1", "patch.diff"),
        }
    });
    app.cache_tool_snapshot("patch:run", &result);
    let patch = app.pending_patch.as_ref().expect("pending patch");
    assert_eq!(patch.alias, "F-0001");
    assert!(patch.rationale.contains("sqlx::query!"));
    assert_eq!(patch.tests.len(), 2);
    assert_eq!(
        patch.guardrail.as_deref(),
        Some("approval.patches = human-required")
    );
    assert_eq!(app.shell_view, ShellView::Patch("F-0001".to_string()));
}

#[test]
fn cache_tool_snapshot_populates_exploit_chain_aliases_and_steps() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let result = serde_json::json!({
        "data": {
            "chains": [{
                "id": "C-0001",
                "name": "Template render chain",
                "overallSeverity": "critical",
                "steps": [{
                    "findingFingerprint": "fp",
                    "role": "template-input",
                    "description": "request body controls template text",
                    "filePath": "app.js",
                    "startLine": 3
                }]
            }]
        }
    });

    app.cache_tool_snapshot("exploit-chain:scan", &result);

    assert_eq!(app.chains.len(), 1);
    assert_eq!(app.chains[0].id, "C-0001");
    assert_eq!(app.chains[0].severity, ChainSeverity::Critical);
    assert_eq!(app.chains[0].title, "Template render chain");

    // Detailed chains (with ordered steps) back the attack-tree visualization.
    assert_eq!(app.exploit_chains.len(), 1);
    assert_eq!(app.exploit_chains[0].title, "Template render chain");
    assert_eq!(app.exploit_chains[0].severity, ChainSeverity::Critical);
    assert_eq!(app.exploit_chains[0].steps.len(), 1);
    assert_eq!(app.exploit_chains[0].steps[0].role, "template-input");
    assert_eq!(app.exploit_chains[0].steps[0].file, "app.js");
    assert_eq!(app.exploit_chains[0].steps[0].line, 3);
}

#[test]
fn cache_tool_snapshot_populates_taint_flow() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let result = serde_json::json!({
        "data": {
            "flows": [{
                "cwe": "CWE-89",
                "severity": "high",
                "stages": [
                    {"message": "source: req.query.id", "filePath": "src/routes.ts", "line": 3},
                    {"message": "sink: db.query", "filePath": "src/db.ts", "line": 7}
                ]
            }]
        }
    });

    app.cache_tool_snapshot("taint-iris:hunt", &result);

    let flow = app.taint_flow.as_ref().expect("taint flow snapshot");
    assert_eq!(flow.cwe, "CWE-89");
    assert_eq!(flow.severity, "high");
    assert_eq!(flow.stages.len(), 2);
    assert_eq!(flow.stages[0].file, "src/routes.ts");
    assert_eq!(flow.stages[0].line, 3);
    assert_eq!(flow.stages[1].message, "sink: db.query");
}

#[test]
fn cache_tool_snapshot_populates_pwn_dashboard_snapshots() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let profile = serde_json::json!({
        "binary": "/tmp/chal",
        "stateId": "abc123",
        "statePath": "/tmp/state.json",
        "arch": "x86-64",
        "needed": []
    });
    app.cache_tool_snapshot("pwn:profile-binary", &profile);
    assert_eq!(
        app.pwn_view.binary,
        Some(std::path::PathBuf::from("/tmp/chal"))
    );
    assert_eq!(
        app.pwn_view.state_path,
        Some(std::path::PathBuf::from("/tmp/state.json"))
    );
    assert!(app.pwn_view.profile_snapshot.is_some());

    let reverse = serde_json::json!({
        "function": "main",
        "revng": {"ok": true, "output": "void main() {}"},
        "dangerousIo": ["gets"]
    });
    app.cache_tool_snapshot("pwn:reverse", &reverse);
    assert_eq!(app.pwn_view.reverse_snapshots.len(), 1);
}

#[test]
fn pwn_run_candidates_requires_confirmation() {
    let input = serde_json::json!({
        "target": "127.0.0.1:31337",
        "stateId": "abc123",
        "maxAttempts": 3,
        "parallelism": 1
    });
    let confirm = confirm_gate_for_tool("pwn:run-candidates", &input, &Default::default())
        .expect("confirmation");
    assert_eq!(confirm.kind, ConfirmKind::PwnCandidateAttempt);
    assert_eq!(confirm.target, "127.0.0.1:31337");
    assert!(confirm
        .rationale
        .as_deref()
        .unwrap_or("")
        .contains("abc123"));
}

#[test]
fn parse_pending_patch_skips_when_required_fields_missing() {
    // alias + rationale + diff are required; missing any of them
    // means the result wasn't a patch payload, so the parser
    // returns None instead of fabricating a patch.
    assert!(parse_pending_patch(&serde_json::json!({})).is_none());
    assert!(parse_pending_patch(&serde_json::json!({"alias": "F-1", "rationale": "x"})).is_none());
    assert!(parse_pending_patch(&serde_json::json!({"alias": "F-1", "diff": "x"})).is_none());
    assert!(parse_pending_patch(&serde_json::json!({"rationale": "x", "diff": "x"})).is_none());
}

#[test]
fn plan_cursor_navigation_and_skip_toggle() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_plan(PlanProposal {
        goal: "test".to_string(),
        summary: "summary".to_string(),
        changes: vec![
            PlanChange::Note {
                text: "first".to_string(),
            },
            PlanChange::Note {
                text: "second".to_string(),
            },
            PlanChange::Note {
                text: "third".to_string(),
            },
        ],
        unsupported: Vec::new(),
    });

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    assert_eq!(app.plan_cursor, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()));
    assert!(app.plan_change_skipped(2));
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    assert_eq!(app.plan_cursor, 1);
    app.discard_pending_plan();
    assert!(app.pending_plan.is_none());
    assert_eq!(app.plan_cursor, 0);
    assert!(app.plan_skipped.is_empty());
}

#[test]
fn activity_command_opens_view_and_creates_session() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;
    assert!(matches!(app.shell_view, ShellView::Home));
    assert!(app.activity.is_none());

    app.handle_command(ShellCommand::Activity);

    assert!(matches!(app.shell_view, ShellView::Activity));
    assert!(
        app.activity.is_some(),
        "/activity should mint a session if none exists"
    );
}

#[test]
fn activity_view_pause_verbose_reset_keys() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Activity);

    // Pause toggle.
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(app.activity.as_ref().unwrap().paused);
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(!app.activity.as_ref().unwrap().paused);

    // Verbose toggle.
    app.handle_key(KeyEvent::new(KeyCode::Char('V'), KeyModifiers::empty()));
    assert!(app.activity.as_ref().unwrap().verbose_subsystems);

    // Reset drops the session.
    app.handle_key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::empty()));
    assert!(app.activity.is_none());
}

#[test]
fn activity_view_renders_dag_rows_and_feed_events() {
    use kuzushi_core::RunTraceStep;

    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Activity);
    let session = app.activity.as_mut().unwrap();
    session.apply_step(
        RunTraceStep::new(1, "tool", "started")
            .with_module_id("semgrep")
            .with_verb("scan"),
    );
    session.apply_step(
        RunTraceStep::new(2, "reasoning", "verdict=likely-tp")
            .with_module_id("triage")
            .with_verb("run"),
    );
    session.apply_step(
        RunTraceStep::new(3, "tool", "task-selector ran")
            .with_module_id("pipeline")
            .with_verb("task-selector"),
    );

    // Use the lower-level renderer directly since we already have an open
    // Activity view + populated session.
    let output = crate::renderer::render_plain_app(&app, 100);
    assert!(output.contains("[semgrep:scan]"));
    assert!(output.contains("[triage:run]"));
    assert!(
        output.contains("subsystems"),
        "hidden pipeline:* events should collapse into the subsystems aggregate, output was: {output}"
    );
    assert!(
        !output.contains("[pipeline:task-selector]"),
        "hidden module events should be filtered from the feed by default"
    );
}

fn assert_plain_output_strict_80(output: &str) {
    assert!(
        !output.contains('\u{1b}'),
        "plain output contained ANSI escape: {output:?}"
    );
    assert!(
        !output
            .chars()
            .any(|ch| ('\u{2500}'..='\u{257f}').contains(&ch)),
        "plain output contained box drawing: {output:?}"
    );
    for line in output.lines() {
        assert!(
            line.chars().count() <= 80,
            "plain line exceeded 80 columns: {line:?}"
        );
    }
}

// ── Security-viz gallery: ungate + auto-open ────────────────────────────────

#[test]
fn scene_command_opens_gallery_without_a_flag() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Scene);
    assert_eq!(app.shell_view, ShellView::Scene(app.scene_page));
}

#[test]
fn viz_page_for_tool_maps_artifacts_to_pages() {
    use crate::scene3d::VizPage;
    assert_eq!(
        viz_page_for_tool("taint-iris:hunt"),
        Some(VizPage::AttackPath)
    );
    assert_eq!(
        viz_page_for_tool("exploit-chain:scan"),
        Some(VizPage::ExploitChain)
    );
    assert_eq!(viz_page_for_tool("threat-model:build"), Some(VizPage::Dfd));
    assert_eq!(viz_page_for_tool("sast:scan"), None);
    assert_eq!(viz_page_for_tool("recon:nmap"), None);
    // Prereq / read-only / non-flow-emitting verbs share a prefix but produce no
    // structured artifact — they must NOT auto-open, or an empty page flashes.
    // (`taint-iris-next:hunt` flattens its taint path into finding text and emits
    // no `data.flows[]`, unlike `taint-iris:hunt`.)
    assert_eq!(viz_page_for_tool("taint-iris-next:hunt"), None);
    assert_eq!(viz_page_for_tool("taint-iris-next:catalog"), None);
    assert_eq!(viz_page_for_tool("taint-iris-next:dataflow-plan"), None);
    assert_eq!(viz_page_for_tool("threat-model:read"), None);
    assert_eq!(viz_page_for_tool("threat-model:methodologies"), None);
}

#[test]
fn viz_page_has_content_tracks_backing_artifacts() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    // Fresh app: nothing generated yet — every artifact-backed page is empty.
    assert!(!app.viz_page_has_content(VizPage::AttackPath));
    assert!(!app.viz_page_has_content(VizPage::ExploitChain));
    assert!(!app.viz_page_has_content(VizPage::Heatmap));
    assert!(!app.viz_page_has_content(VizPage::Dfd));

    // A cached taint flow gives the attack-path page something to draw.
    app.cache_tool_snapshot(
        "taint-iris:hunt",
        &serde_json::json!({
            "data": {"flows": [{"cwe": "CWE-89", "severity": "high", "stages": [
                {"message": "source", "filePath": "a.ts", "line": 1}
            ]}]}
        }),
    );
    assert!(app.viz_page_has_content(VizPage::AttackPath));
}

#[test]
fn auto_open_viz_page_switches_view_when_enabled() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.auto_open_viz = true;
    app.auto_open_viz_page(VizPage::Dfd);
    assert_eq!(app.shell_view, ShellView::Scene(VizPage::Dfd));
    assert_eq!(app.scene_page, VizPage::Dfd);
}

#[test]
fn auto_open_viz_page_is_inert_when_disabled() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.auto_open_viz = false;
    let before = app.shell_view.clone();
    app.auto_open_viz_page(VizPage::Dfd);
    assert_eq!(app.shell_view, before);
}

#[test]
fn scan_completion_auto_opens_the_findings_heatmap() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.auto_open_viz = true;
    app.apply_scan_finished("run-viz".to_string(), 2);
    assert_eq!(app.shell_view, ShellView::Scene(VizPage::Heatmap));
}

#[test]
fn scan_completion_respects_viz_opt_out() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.auto_open_viz = false;
    let before = app.shell_view.clone();
    app.apply_scan_finished("run-viz".to_string(), 2);
    assert_eq!(app.shell_view, before);
}

#[test]
fn clean_scan_does_not_auto_open_an_empty_heatmap() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.auto_open_viz = true;
    let before = app.shell_view.clone();
    app.apply_scan_finished("run-clean".to_string(), 0);
    assert_eq!(
        app.shell_view, before,
        "a 0-finding scan is a pass, not a heatmap to yank to"
    );
}
