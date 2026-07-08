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
    parse_command, ContextCommand, PatchCommand, ReviewDecisionCommand, SastTaskCommand,
    SastTaskModeCommand, ShellCommand, WorkspaceCommand,
};
use crate::ui_view_models::ui_run_artifact_relative_path;
use kuzushi_core::run_artifacts::load_run_failures;
use kuzushi_core::{
    load_persistent_threat_model, load_run_summary, run_dir, save_persistent_threat_model,
    AttachmentRecord, FindingStore, OptionScope, OptionTarget, RuntimeConfig, RuntimeKind,
    Severity, ToolOptionStore, TriageOutcome, TriageVerdict,
};
use std::ffi::OsString;
use std::fs;

/// Serializes tests that mutate process-wide provider-key env vars.
/// `EnvVarGuard` only saves/restores a variable's value; it does not stop
/// two env-mutating tests on separate `cargo test` threads from clobbering
/// each other's `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` mid-body and racing
/// model resolution. Acquire this as the first line of such a test and
/// hold the guard for the whole body so env mutation stays single-threaded.
static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    prior: Option<OsString>,
}

impl EnvVarGuard {
    fn unset(key: &'static str) -> Self {
        let prior = std::env::var_os(key);
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, prior }
    }

    fn set(key: &'static str, value: &str) -> Self {
        let prior = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, prior }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.prior {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

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
    app.drain_next_tool_event_for_test(WORKER_TEST_TIMEOUT)
        .unwrap();
}

fn press_key(app: &mut ShellApp, key: KeyEvent) -> bool {
    update_and_execute_effects(app, Msg::Term(TermEvent::Key(key)))
}

fn paste_text(app: &mut ShellApp, text: &str) -> bool {
    update_and_execute_effects(app, Msg::Term(TermEvent::Paste(text.to_string())))
}

fn mouse_event(app: &mut ShellApp, mouse: crossterm::event::MouseEvent) -> bool {
    update_and_execute_effects(app, Msg::Term(TermEvent::Mouse(mouse)))
}

fn submit_shell_line(app: &mut ShellApp, raw: &str) -> bool {
    app.set_input(raw);
    update_and_execute_effects(
        app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    )
}

fn run_command(app: &mut ShellApp, command: ShellCommand) -> bool {
    update_and_execute_effects(app, Msg::Cmd(command))
}

const WORKER_TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Drive a prerequisite chain to completion: while a chain is active,
/// drain background tool events and auto-reuse any pending reuse-or-
/// regenerate prompts.  Used by tests that exercise tools whose chain
/// includes deterministic prereqs (e.g. carlini → context:build →
/// threat-model:build).
#[allow(dead_code)]
fn drain_chain_with_auto_reuse(app: &mut ShellApp) {
    loop {
        if app.engagement.has_pending_prereq_prompt() {
            let effects = app.resolve_prereq_prompt(true);
            EffectRuntime::execute(app, effects);
            continue;
        }
        if !app.tool_is_running() && !app.engagement.has_pending_chain() {
            return;
        }
        app.drain_next_tool_event_for_test(WORKER_TEST_TIMEOUT)
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
    app.config_mut().model = None;

    run_command(&mut app, ShellCommand::Use("offense-review".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"maxActors":1,"runsPerActor":1}"#.to_string()),
        },
    );

    let plan = app.engagement.pending_prereq_prompt().unwrap();
    assert_eq!(app.running_tool_name(), None);
    assert_eq!(app.config().model, None);
    assert_eq!(plan.final_tool, "offense-review:threat-hunt");
    assert!(plan.steps.iter().any(|step| step.model_backed
        && step.artifact_state == PrereqArtifactState::Missing
        && step.cost_hint.contains("token cost unknown")));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "system" && line.body.contains("review approve/reuse/regenerate/cancel")
    }));
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("running automatically")));
}

#[test]
fn taint_iris_next_run_dot_uses_split_public_default_tool() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::Use("taint-iris-next".to_string()));

    assert_eq!(
        app.default_tool_for_focused_module().as_deref(),
        Some("taint-iris-next:dataflow-plan")
    );
    assert!(app
        .registry()
        .resolve_tool("taint-iris-next:hunt")
        .is_some());
    assert!(!app
        .registry()
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
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()),
    );

    assert!(
        app.engagement.has_pending_chain(),
        "c must not mean cancel here"
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()),
    );

    assert!(!app.engagement.has_pending_chain());
    assert!(!app.engagement.has_pending_prereq_prompt());
    assert_eq!(app.running_tool_name(), None);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "system" && line.body.contains("prerequisite plan cancelled")
    }));
}

#[test]
fn prereq_plan_approval_returns_advance_effect_without_inline_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let start_effects = app.start_prereq_chain(
        prereq_steps_for("threat-model:build", tmp.path()),
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        None,
    );
    assert!(start_effects.is_empty());

    let effects = app.resolve_prereq_plan(PrereqPlanAction::Approve);

    assert_eq!(app.running_tool_name(), None);
    assert!(!app.engagement.has_pending_prereq_prompt());
    assert!(app.engagement.pending_chain_approved());
    let [ShellEffect::AdvancePrereqChain(advance)] = effects.as_slice() else {
        panic!("expected prereq advance effect");
    };
    assert_eq!(advance.target.as_deref(), app.target());
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
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()),
    );

    assert_eq!(app.running_tool_name(), Some("findings:list"));
    assert!(!app.engagement.has_pending_prereq_prompt());
    assert!(app.log_lines().iter().any(|line| {
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
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );

    assert_eq!(app.running_tool_name(), Some("context:build"));
    assert!(!app.engagement.has_pending_prereq_prompt());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "system" && line.body.contains("running after prerequisite approval")
    }));
    drain_tool(&mut app);
    if app.tool_is_running() {
        drain_tool(&mut app);
    }
}

#[test]
fn trusted_workflow_auto_accept_explicitly_starts_missing_prereq() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.session_mut().set_trusted_workflow_auto_accept(true);

    let effects = app.start_prereq_chain(
        prereq_steps_for("threat-model:build", tmp.path()),
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        None,
    );
    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.running_tool_name(), Some("context:build"));
    assert!(!app.engagement.has_pending_prereq_prompt());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "system" && line.body.contains("trusted workflow auto-accepted")
    }));
    drain_tool(&mut app);
    if app.tool_is_running() {
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

    let activity = app.live_activity().unwrap();
    assert_eq!(activity.phase, LiveActivityPhase::Reading);
    assert_eq!(activity.subject, "findings:list");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "activity" && line.body.contains("reading: findings:list") }));
    drain_tool(&mut app);
    assert!(app
        .live_activity()
        .is_some_and(|activity| activity.phase == LiveActivityPhase::Completed));
}

#[test]
fn background_tool_waits_for_pending_prompt_mutation_decision() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mutation = kuzushi_core::PromptMutation::new(
        "findings",
        "list",
        "tighten finding list prompt",
        "operator",
    );
    kuzushi_core::append_prompt_mutation(&workspace, &mutation).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.start_background_tool(
        "findings:list".to_string(),
        serde_json::json!({}),
        workspace,
        tool_run_status("findings:list"),
        None,
    );

    assert_eq!(app.running_tool_name(), None);
    assert_eq!(app.shell_view(), ShellView::PromptsEditor);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "prompt" && line.body.contains("blocked by pending prompt mutation")
    }));
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

    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("carlini-threat-hunt:run".to_string()),
            input: Some(r#"{"maxActors":1}"#.to_string()),
        },
    );

    assert_eq!(app.running_tool_name(), None);
    assert!(!app.engagement.has_pending_chain());
    assert_eq!(app.shell_view(), ShellView::Threat);
    assert_eq!(app.router.threat().view(), ThreatView::Summary);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "threats" && line.body.contains("apply or reject the pending threat")
    }));
    assert!(app
        .live_activity()
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

    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("offense-review:threat-hunt".to_string()),
            input: Some(r#"{"maxActors":1}"#.to_string()),
        },
    );

    assert_eq!(app.running_tool_name(), None);
    assert!(!app.engagement.has_pending_chain());
    assert_eq!(app.shell_view(), ShellView::Threat);
    assert_eq!(app.router.threat().view(), ThreatView::Summary);
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
{"ok":true,"text":"Run context build, then next","costUsd":0.034}
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
        .record_run_started("run-variant", workspace.root(), "running")
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
        .record_run_finished("run-variant", "completed", 1)
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
  *"Taint IRIS Next agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"selectedCwes":[{"cwe":"CWE-89","reason":"database query uses request input","catalogSignals":["sink: query("],"sourceSpec":"request query parameters","sinkSpec":"database query calls","sanitizerSpec":"parameterized query APIs","customCweRationale":""}],"findings":[{"title":"Request input reaches SQL query","cwe":"CWE-89","severity":"high","confidence":"medium","evidenceLevel":"linked","filePath":"src/db.ts","startLine":1,"message":"The request query is concatenated into a SQL query.","sourceSinkTrace":"req.query.q -> db.query","catalogSignals":["sink: query("],"customCweRationale":"","taintPath":[{"filePath":"src/db.ts","line":1,"message":"source and sink","snippet":"db.query(req.query.q)"}]}],"triage":[{"status":"finding","cwe":"CWE-89","evidenceLevel":"linked","rationale":"request data reaches SQL query","filePath":"src/db.ts","line":1,"catalogSignals":["sink: query("]}],"notes":[]}}
JSON
    ;;
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
{"ok":true,"structured":{"fingerprint":"fp-from-bridge","exploitable":true,"poc_payload":"fixture-marker","poc_description":"fixture marker reaches review sink","attack_vector":"fixture marker path","preconditions":["local fixture"],"confidence":0.84,"proof_level":3,"proof_verdict":"exploited"}}
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
fn git_is_unavailable() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
}

#[cfg(unix)]
fn git(dir: &PathBuf, args: &[&str]) {
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

#[cfg(unix)]
fn git_head(dir: &PathBuf) -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
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
    run_command(&mut app, parse_command("logs"));
    assert!(matches!(app.shell_view(), ShellView::Logs));

    // Aliases (log, transcript) reach the same view.
    app.set_shell_view(ShellView::Home);
    run_command(&mut app, parse_command("log"));
    assert!(matches!(app.shell_view(), ShellView::Logs));

    app.set_shell_view(ShellView::Home);
    run_command(&mut app, parse_command("transcript"));
    assert!(matches!(app.shell_view(), ShellView::Logs));
}

#[test]
fn logs_view_routes_j_k_and_page_keys_to_logs_scroll() {
    // M1 §1.1: while in the Logs view, j/k and PgDn/PgUp must drive the
    // dedicated logs route scroll rather than the fallback route scroll
    // — otherwise the transcript would visually stay pinned while the
    // generic offset advances.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Logs);
    app.router.default_scroll_mut().reset();
    app.router.logs_mut().open();

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.logs().scroll(), 10);
    assert_eq!(app.router.default_scroll().offset(), 0);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.logs().scroll(), 11);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.logs().scroll(), 0);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.logs().scroll(), usize::MAX);
}

#[test]
fn shell_log_retention_is_bounded_to_recent_lines() {
    let mut app = ShellApp::new(V2Config::default(), None);

    for index in 0..(LOG_LINE_CAPACITY + 25) {
        app.log("test", format!("line-{index}"));
    }

    assert_eq!(app.log_len(), LOG_LINE_CAPACITY);
    assert_eq!(app.log_lines().first().unwrap().body, "line-25");
    assert_eq!(
        app.log_lines().last().unwrap().body,
        format!("line-{}", LOG_LINE_CAPACITY + 24)
    );
}

#[test]
fn help_command_routes_to_rust_shell_help_without_removed_cli_paths() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, parse_command("/help"));

    assert_eq!(app.shell_view(), ShellView::Help);
    let help_log = app
        .log_lines()
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
        .record_run_started("run-complete", workspace.root(), "completed")
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
    app.findings_mut().clear();
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-active-123".to_string()),
        target: workspace.root().to_path_buf(),
        stage: "completed".to_string(),
        findings_count: 1,
        running: false,
        abort_requested: false,
        error: None,
    }));
    app.domain_mut().kb_view_mut().attachments = vec![AttachmentRecord {
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
    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(app.input(), "/context");

    app.set_input("task block co");
    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(app.input(), "task block codeql");
}

#[test]
fn command_reducer_updates_model_without_terminal() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(
        &mut app,
        ShellCommand::Model(Some("openai:gpt-4.1".to_string())),
    );

    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-4.1"));
    assert!(app.log_lines().iter().any(|line| line.prefix == "model"));
}

#[test]
fn model_command_reducer_returns_persist_effect_without_writing_config() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::Model(Some("openai:gpt-4.1 high".to_string()))),
    );

    assert!(result.changed);
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-4.1"));
    assert_eq!(app.session_thinking_level(), Some("high"));
    let effect = global_model_persist_effect(&result.effects).expect("model persist effect");
    assert_eq!(effect.model, "openai:gpt-4.1");
    assert_eq!(effect.thinking_level.as_deref(), Some("high"));
    assert!(
        !app.log_lines()
            .iter()
            .any(|line| line.body.contains("saved global model")),
        "config persistence logging belongs to the effect runtime"
    );
}

#[test]
fn command_reducer_focuses_existing_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Use("semgrep".to_string()));

    assert_eq!(app.focused_module(), Some("semgrep"));
}

#[test]
fn run_tool_reducer_returns_prepare_effect_without_preparing_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app.reduce_run_tool(Some("semgrep:scan".to_string()), None);

    assert_eq!(effects.len(), 1);
    let prepare = run_tool_prepare(&effects).expect("run tool prepare effect");
    assert_eq!(prepare.tool_name, "semgrep:scan");
    assert_eq!(prepare.input, None);
    assert!(prepare.target.as_ref().is_some_and(|path| path.exists()));
    assert!(!app.tool_is_running());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn run_tool_prepare_effect_returns_prepared_launch_without_spawning_worker() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let prepare = RunToolPreparation {
        tool_name: "semgrep:scan".to_string(),
        input: None,
        target: Some(workspace.root().to_path_buf()),
    };

    let effects = app.prepare_run_tool_launch(prepare);

    let launch = run_tool_launch(&effects).expect("prepared launch effect");
    assert_eq!(launch.tool_name, "semgrep:scan");
    assert_eq!(launch.workspace.root(), workspace.root());
    assert!(launch.input.is_object());
    assert!(!app.tool_is_running());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn scan_command_reducer_defers_guided_scan_open_to_effect_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);

    let effects = app
        .reduce_command_effects(&ShellCommand::Scan(Some(temp.path().to_path_buf())))
        .expect("scan command should be effect-routed");

    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::OpenGuidedScan(GuidedScanOpen { .. })]
    ));
    assert!(app.target().is_none());
    assert_ne!(app.shell_view(), ShellView::PlanningPicker);

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(
        app.target().and_then(|path| path.canonicalize().ok()),
        temp.path().canonicalize().ok()
    );
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn scan_reducer_returns_prepare_effect_without_preparing_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app.reduce_scan_start(Some(tmp.path().to_path_buf()), None);

    assert_eq!(effects.len(), 1);
    let prepare = scan_prepare(&effects).expect("scan prepare effect");
    assert!(prepare.target.as_ref().is_some_and(|path| path.exists()));
    assert!(prepare.explicit_input.is_none());
    assert!(app.scan_is_none());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn scan_prepare_effect_returns_start_effect_without_spawning_worker() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let prepare = ScanStartPreparation {
        target: Some(workspace.root().to_path_buf()),
        explicit_input: None,
    };

    let effects = app.prepare_scan_start_effect(prepare);

    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], ShellEffect::StartScan(_)));
    assert!(app.scan_is_none());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn ask_reducer_returns_dispatch_effect_without_spawning_worker() {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);

    let effects = app.reduce_ask_agent("What should I run first?");

    assert_eq!(effects.len(), 1);
    match effects.into_iter().next().unwrap() {
        ShellEffect::DispatchAgent(_) => {}
        ShellEffect::ApplyReviewedPatch(_)
        | ShellEffect::ApplySastTaskOptions(_)
        | ShellEffect::ApplyThreatPatch(_)
        | ShellEffect::AuthLogin(_)
        | ShellEffect::ActivateTarget(_)
        | ShellEffect::AdvancePrereqChain(_)
        | ShellEffect::AbortForBudget
        | ShellEffect::CancelActiveJobs
            | ShellEffect::CancelJob(_)
        | ShellEffect::ClearConversation
        | ShellEffect::ContinuePastBudget
        | ShellEffect::ShowKnowledgeBase(_)
        | ShellEffect::AttachKnowledgeBaseSource(_)
        | ShellEffect::DetachKnowledgeBaseSource(_)
        | ShellEffect::ReparseKnowledgeBaseSource(_)
        | ShellEffect::OpenActivity(_)
        | ShellEffect::OpenFilePicker
        | ShellEffect::OpenGuidedScan(_)
        | ShellEffect::PrepareScan(_)
        | ShellEffect::PrepareRunTool(_)
        | ShellEffect::DispatchRunTool(_)
        | ShellEffect::DispatchNextPlanningTask(_)
        | ShellEffect::RefreshDeterministicRecommendations(_)
        | ShellEffect::DiffPromptOverride(_)
        | ShellEffect::EditPromptOverride(_)
        | ShellEffect::ListPromptOverrides(_)
        | ShellEffect::LoadDynamicModule(_)
        | ShellEffect::PauseActiveWork
        | ShellEffect::PersistCommandHistory
        | ShellEffect::PersistGlobalModelSelection(_)
        | ShellEffect::PersistPlanningOptionOverride(_)
        | ShellEffect::PersistOptions(_)
        | ShellEffect::ResetPromptOverride(_)
        | ShellEffect::ResumeSession(_)
        | ShellEffect::RequestExitAbort
        | ShellEffect::RequestShellQuit
        | ShellEffect::Quit
        | ShellEffect::FinishShellQuit
        | ShellEffect::RecordAgentRun(_)
        | ShellEffect::RecordPromptMutation(_)
        | ShellEffect::RecordScanRun(_)
        | ShellEffect::RecordScanStageTrace(_)
        | ShellEffect::RecordToolRun(_)
        | ShellEffect::RecordReviewDecision(_)
        | ShellEffect::ResetHouseRules(_)
        | ShellEffect::RefreshContextView
        | ShellEffect::RefreshFindings(_)
        | ShellEffect::RefreshHouseRules(_)
        | ShellEffect::ReportFilteredFindingMovement(_)
        | ShellEffect::FinalizeGuidedScanOpen
        | ShellEffect::FinalizeWorkbenchOpen(_)
        | ShellEffect::FinalizeOpenFinding(_)
        | ShellEffect::FinalizeSastTaskCommand(_)
        | ShellEffect::HydrateSceneSnapshots(_)
        | ShellEffect::FinalizeScanCompletion(_)
        | ShellEffect::RefreshPwnState
        | ShellEffect::RefreshProgramScope
        | ShellEffect::OpenFinding(_)
        | ShellEffect::OpenRunArtifact(_)
        | ShellEffect::SelectComponent(_)
        | ShellEffect::BuildContext(_)
        | ShellEffect::FireNextApprovedStrategy(_)
        | ShellEffect::RecordStrategyCorrection(_)
        | ShellEffect::UpdateStrategyProposalStatus(_)
        | ShellEffect::SetSessionEnv(_)
        | ShellEffect::ShowAuthStatus(_)
        | ShellEffect::ShowContextStatus
        | ShellEffect::ShowHouseRules(_)
        | ShellEffect::ShowPromptOverride(_)
        | ShellEffect::ShowWorkspaceStatus
        | ShellEffect::StartOfflineDemoFixtureScan
        | ShellEffect::StartPlanner(_)
        | ShellEffect::StartScan(_)
        | ShellEffect::StartThreat(_)
        | ShellEffect::SwitchTargetRevision(_)
        | ShellEffect::UpdatePromptMutationStatus(_)
        | ShellEffect::WaitForAbortCleanup
        | ShellEffect::WorkspaceExportFindings(_)
        | ShellEffect::WorkspaceScopeInit(_)
        | ShellEffect::WriteHouseRules(_)
        | ShellEffect::WritePromptOverride(_) => {
            panic!("expected agent dispatch effect")
        }
    }
    assert!(app.agent_chat().is_none());
    assert!(!app.jobs().is_running(JobKind::Agent));
    assert!(app.live_activity().is_none());
    assert!(!app.log_lines().iter().any(|line| line.prefix == "agent"));
}

#[test]
fn planner_reducer_returns_start_effect_without_spawning_worker() {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);

    let effects = app.reduce_planner_start("tighten module option policy");

    assert_eq!(effects.len(), 1);
    match effects.into_iter().next().unwrap() {
        ShellEffect::StartPlanner(_) => {}
        ShellEffect::ApplyReviewedPatch(_)
        | ShellEffect::ApplySastTaskOptions(_)
        | ShellEffect::ApplyThreatPatch(_)
        | ShellEffect::AuthLogin(_)
        | ShellEffect::ActivateTarget(_)
        | ShellEffect::AdvancePrereqChain(_)
        | ShellEffect::AbortForBudget
        | ShellEffect::CancelActiveJobs
            | ShellEffect::CancelJob(_)
        | ShellEffect::ClearConversation
        | ShellEffect::ContinuePastBudget
        | ShellEffect::ShowKnowledgeBase(_)
        | ShellEffect::AttachKnowledgeBaseSource(_)
        | ShellEffect::DetachKnowledgeBaseSource(_)
        | ShellEffect::ReparseKnowledgeBaseSource(_)
        | ShellEffect::OpenActivity(_)
        | ShellEffect::OpenFilePicker
        | ShellEffect::OpenGuidedScan(_)
        | ShellEffect::DispatchAgent(_)
        | ShellEffect::DispatchNextPlanningTask(_)
        | ShellEffect::PrepareScan(_)
        | ShellEffect::PrepareRunTool(_)
        | ShellEffect::DispatchRunTool(_)
        | ShellEffect::RefreshDeterministicRecommendations(_)
        | ShellEffect::DiffPromptOverride(_)
        | ShellEffect::EditPromptOverride(_)
        | ShellEffect::ListPromptOverrides(_)
        | ShellEffect::LoadDynamicModule(_)
        | ShellEffect::PauseActiveWork
        | ShellEffect::PersistCommandHistory
        | ShellEffect::PersistGlobalModelSelection(_)
        | ShellEffect::PersistPlanningOptionOverride(_)
        | ShellEffect::PersistOptions(_)
        | ShellEffect::ResetPromptOverride(_)
        | ShellEffect::ResumeSession(_)
        | ShellEffect::RequestExitAbort
        | ShellEffect::RequestShellQuit
        | ShellEffect::Quit
        | ShellEffect::FinishShellQuit
        | ShellEffect::RecordAgentRun(_)
        | ShellEffect::RecordPromptMutation(_)
        | ShellEffect::RecordScanRun(_)
        | ShellEffect::RecordScanStageTrace(_)
        | ShellEffect::RecordToolRun(_)
        | ShellEffect::RecordReviewDecision(_)
        | ShellEffect::ResetHouseRules(_)
        | ShellEffect::RefreshContextView
        | ShellEffect::RefreshFindings(_)
        | ShellEffect::RefreshHouseRules(_)
        | ShellEffect::ReportFilteredFindingMovement(_)
        | ShellEffect::FinalizeGuidedScanOpen
        | ShellEffect::FinalizeWorkbenchOpen(_)
        | ShellEffect::FinalizeOpenFinding(_)
        | ShellEffect::FinalizeSastTaskCommand(_)
        | ShellEffect::HydrateSceneSnapshots(_)
        | ShellEffect::FinalizeScanCompletion(_)
        | ShellEffect::RefreshPwnState
        | ShellEffect::RefreshProgramScope
        | ShellEffect::OpenFinding(_)
        | ShellEffect::OpenRunArtifact(_)
        | ShellEffect::SelectComponent(_)
        | ShellEffect::BuildContext(_)
        | ShellEffect::FireNextApprovedStrategy(_)
        | ShellEffect::RecordStrategyCorrection(_)
        | ShellEffect::UpdateStrategyProposalStatus(_)
        | ShellEffect::SetSessionEnv(_)
        | ShellEffect::ShowAuthStatus(_)
        | ShellEffect::ShowContextStatus
        | ShellEffect::ShowHouseRules(_)
        | ShellEffect::ShowPromptOverride(_)
        | ShellEffect::ShowWorkspaceStatus
        | ShellEffect::StartOfflineDemoFixtureScan
        | ShellEffect::StartScan(_)
        | ShellEffect::StartThreat(_)
        | ShellEffect::SwitchTargetRevision(_)
        | ShellEffect::UpdatePromptMutationStatus(_)
        | ShellEffect::WaitForAbortCleanup
        | ShellEffect::WorkspaceExportFindings(_)
        | ShellEffect::WorkspaceScopeInit(_)
        | ShellEffect::WriteHouseRules(_)
        | ShellEffect::WritePromptOverride(_) => panic!("expected planner start effect"),
    }
    assert!(!app.planner_running());
    assert!(app.live_activity().is_none());
}

#[test]
fn threat_reducers_return_start_effects_without_spawning_workers() {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);

    let regen_effects = app.reduce_threat_regen();
    let ask_effects = app.reduce_threat_ask("what changed in the threat model?");

    assert_eq!(regen_effects.len(), 1);
    assert_eq!(ask_effects.len(), 1);
    match regen_effects.into_iter().next().unwrap() {
        ShellEffect::StartThreat(_) => {}
        ShellEffect::ApplyReviewedPatch(_)
        | ShellEffect::ApplySastTaskOptions(_)
        | ShellEffect::ApplyThreatPatch(_)
        | ShellEffect::AuthLogin(_)
        | ShellEffect::ActivateTarget(_)
        | ShellEffect::AdvancePrereqChain(_)
        | ShellEffect::AbortForBudget
        | ShellEffect::CancelActiveJobs
            | ShellEffect::CancelJob(_)
        | ShellEffect::ClearConversation
        | ShellEffect::ContinuePastBudget
        | ShellEffect::ShowKnowledgeBase(_)
        | ShellEffect::AttachKnowledgeBaseSource(_)
        | ShellEffect::DetachKnowledgeBaseSource(_)
        | ShellEffect::ReparseKnowledgeBaseSource(_)
        | ShellEffect::OpenActivity(_)
        | ShellEffect::OpenFilePicker
        | ShellEffect::OpenGuidedScan(_)
        | ShellEffect::DispatchAgent(_)
        | ShellEffect::DispatchNextPlanningTask(_)
        | ShellEffect::PrepareScan(_)
        | ShellEffect::PrepareRunTool(_)
        | ShellEffect::DispatchRunTool(_)
        | ShellEffect::RefreshDeterministicRecommendations(_)
        | ShellEffect::DiffPromptOverride(_)
        | ShellEffect::EditPromptOverride(_)
        | ShellEffect::ListPromptOverrides(_)
        | ShellEffect::LoadDynamicModule(_)
        | ShellEffect::PauseActiveWork
        | ShellEffect::PersistCommandHistory
        | ShellEffect::PersistGlobalModelSelection(_)
        | ShellEffect::PersistPlanningOptionOverride(_)
        | ShellEffect::PersistOptions(_)
        | ShellEffect::ResetPromptOverride(_)
        | ShellEffect::ResumeSession(_)
        | ShellEffect::RequestExitAbort
        | ShellEffect::RequestShellQuit
        | ShellEffect::Quit
        | ShellEffect::FinishShellQuit
        | ShellEffect::RecordAgentRun(_)
        | ShellEffect::RecordPromptMutation(_)
        | ShellEffect::RecordScanRun(_)
        | ShellEffect::RecordScanStageTrace(_)
        | ShellEffect::RecordToolRun(_)
        | ShellEffect::RecordReviewDecision(_)
        | ShellEffect::ResetHouseRules(_)
        | ShellEffect::RefreshContextView
        | ShellEffect::RefreshFindings(_)
        | ShellEffect::RefreshHouseRules(_)
        | ShellEffect::ReportFilteredFindingMovement(_)
        | ShellEffect::FinalizeGuidedScanOpen
        | ShellEffect::FinalizeWorkbenchOpen(_)
        | ShellEffect::FinalizeOpenFinding(_)
        | ShellEffect::FinalizeSastTaskCommand(_)
        | ShellEffect::HydrateSceneSnapshots(_)
        | ShellEffect::FinalizeScanCompletion(_)
        | ShellEffect::RefreshPwnState
        | ShellEffect::RefreshProgramScope
        | ShellEffect::OpenFinding(_)
        | ShellEffect::OpenRunArtifact(_)
        | ShellEffect::SelectComponent(_)
        | ShellEffect::BuildContext(_)
        | ShellEffect::FireNextApprovedStrategy(_)
        | ShellEffect::RecordStrategyCorrection(_)
        | ShellEffect::UpdateStrategyProposalStatus(_)
        | ShellEffect::SetSessionEnv(_)
        | ShellEffect::ShowAuthStatus(_)
        | ShellEffect::ShowContextStatus
        | ShellEffect::ShowHouseRules(_)
        | ShellEffect::ShowPromptOverride(_)
        | ShellEffect::ShowWorkspaceStatus
        | ShellEffect::StartOfflineDemoFixtureScan
        | ShellEffect::StartPlanner(_)
        | ShellEffect::StartScan(_)
        | ShellEffect::SwitchTargetRevision(_)
        | ShellEffect::UpdatePromptMutationStatus(_)
        | ShellEffect::WaitForAbortCleanup
        | ShellEffect::WorkspaceExportFindings(_)
        | ShellEffect::WorkspaceScopeInit(_)
        | ShellEffect::WriteHouseRules(_)
        | ShellEffect::WritePromptOverride(_) => panic!("expected threat start effect"),
    }
    match ask_effects.into_iter().next().unwrap() {
        ShellEffect::StartThreat(_) => {}
        ShellEffect::ApplyReviewedPatch(_)
        | ShellEffect::ApplySastTaskOptions(_)
        | ShellEffect::ApplyThreatPatch(_)
        | ShellEffect::AuthLogin(_)
        | ShellEffect::ActivateTarget(_)
        | ShellEffect::AdvancePrereqChain(_)
        | ShellEffect::AbortForBudget
        | ShellEffect::CancelActiveJobs
            | ShellEffect::CancelJob(_)
        | ShellEffect::ClearConversation
        | ShellEffect::ContinuePastBudget
        | ShellEffect::ShowKnowledgeBase(_)
        | ShellEffect::AttachKnowledgeBaseSource(_)
        | ShellEffect::DetachKnowledgeBaseSource(_)
        | ShellEffect::ReparseKnowledgeBaseSource(_)
        | ShellEffect::OpenActivity(_)
        | ShellEffect::OpenFilePicker
        | ShellEffect::OpenGuidedScan(_)
        | ShellEffect::DispatchAgent(_)
        | ShellEffect::DispatchNextPlanningTask(_)
        | ShellEffect::PrepareScan(_)
        | ShellEffect::PrepareRunTool(_)
        | ShellEffect::DispatchRunTool(_)
        | ShellEffect::RefreshDeterministicRecommendations(_)
        | ShellEffect::DiffPromptOverride(_)
        | ShellEffect::EditPromptOverride(_)
        | ShellEffect::ListPromptOverrides(_)
        | ShellEffect::LoadDynamicModule(_)
        | ShellEffect::PauseActiveWork
        | ShellEffect::PersistCommandHistory
        | ShellEffect::PersistGlobalModelSelection(_)
        | ShellEffect::PersistPlanningOptionOverride(_)
        | ShellEffect::PersistOptions(_)
        | ShellEffect::ResetPromptOverride(_)
        | ShellEffect::ResumeSession(_)
        | ShellEffect::RequestExitAbort
        | ShellEffect::RequestShellQuit
        | ShellEffect::Quit
        | ShellEffect::FinishShellQuit
        | ShellEffect::RecordAgentRun(_)
        | ShellEffect::RecordPromptMutation(_)
        | ShellEffect::RecordScanRun(_)
        | ShellEffect::RecordScanStageTrace(_)
        | ShellEffect::RecordToolRun(_)
        | ShellEffect::RecordReviewDecision(_)
        | ShellEffect::ResetHouseRules(_)
        | ShellEffect::RefreshContextView
        | ShellEffect::RefreshFindings(_)
        | ShellEffect::RefreshHouseRules(_)
        | ShellEffect::ReportFilteredFindingMovement(_)
        | ShellEffect::FinalizeGuidedScanOpen
        | ShellEffect::FinalizeWorkbenchOpen(_)
        | ShellEffect::FinalizeOpenFinding(_)
        | ShellEffect::FinalizeSastTaskCommand(_)
        | ShellEffect::HydrateSceneSnapshots(_)
        | ShellEffect::FinalizeScanCompletion(_)
        | ShellEffect::RefreshPwnState
        | ShellEffect::RefreshProgramScope
        | ShellEffect::OpenFinding(_)
        | ShellEffect::OpenRunArtifact(_)
        | ShellEffect::SelectComponent(_)
        | ShellEffect::BuildContext(_)
        | ShellEffect::FireNextApprovedStrategy(_)
        | ShellEffect::RecordStrategyCorrection(_)
        | ShellEffect::UpdateStrategyProposalStatus(_)
        | ShellEffect::SetSessionEnv(_)
        | ShellEffect::ShowAuthStatus(_)
        | ShellEffect::ShowContextStatus
        | ShellEffect::ShowHouseRules(_)
        | ShellEffect::ShowPromptOverride(_)
        | ShellEffect::ShowWorkspaceStatus
        | ShellEffect::StartOfflineDemoFixtureScan
        | ShellEffect::StartPlanner(_)
        | ShellEffect::StartScan(_)
        | ShellEffect::SwitchTargetRevision(_)
        | ShellEffect::UpdatePromptMutationStatus(_)
        | ShellEffect::WaitForAbortCleanup
        | ShellEffect::WorkspaceExportFindings(_)
        | ShellEffect::WorkspaceScopeInit(_)
        | ShellEffect::WriteHouseRules(_)
        | ShellEffect::WritePromptOverride(_) => panic!("expected threat start effect"),
    }
    assert!(!app.threat_worker_running());
    assert!(app.live_activity().is_none());
}

#[test]
fn option_reducers_return_persist_effects_only_for_durable_scopes() {
    let mut session_app = ShellApp::new(V2Config::default(), None);
    let session_effects = session_app.reduce_set_option(false, "ui.auto_open_activity", "false");

    assert!(session_effects.is_empty());
    assert!(!session_app.ui().auto_open_activity());
    assert_eq!(
        session_app
            .option_store()
            .values_for(OptionScope::Session, &OptionTarget::All)
            .and_then(|values| values.get("ui.auto_open_activity")),
        Some(&serde_json::json!(false))
    );

    let mut global_app = ShellApp::new(V2Config::default(), None);
    let global_effects = global_app.reduce_set_option(true, "ui.auto_open_activity", "false");

    assert_eq!(
        persist_option_scope(&global_effects),
        Some(OptionScope::Global)
    );
    assert!(!global_app.ui().auto_open_activity());
    assert_eq!(
        global_app
            .option_store()
            .values_for(OptionScope::Global, &OptionTarget::All)
            .and_then(|values| values.get("ui.auto_open_activity")),
        Some(&serde_json::json!(false))
    );

    let unset_effects = global_app.reduce_unset_option(true, "ui.auto_open_activity");

    assert_eq!(
        persist_option_scope(&unset_effects),
        Some(OptionScope::Global)
    );
    assert!(global_app
        .option_store()
        .values_for(OptionScope::Global, &OptionTarget::All)
        .and_then(|values| values.get("ui.auto_open_activity"))
        .is_none());
}

#[test]
fn command_effect_reducer_routes_existing_effectful_commands() {
    assert_eq!(
        command_effect_kind(ShellCommand::Cancel),
        Some(EffectKind::Cancel)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Clear),
        Some(EffectKind::ClearConversation)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Ask("What next?".to_string())),
        Some(EffectKind::Agent)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Plan("map authz drift".to_string())),
        Some(EffectKind::Planner)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Auth),
        Some(EffectKind::ShowAuthStatus)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Context(ContextCommand::Status)),
        Some(EffectKind::ShowContextStatus)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Context(ContextCommand::Build)),
        Some(EffectKind::BuildContext)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::KnowledgeBase(Some("context".to_string()))),
        Some(EffectKind::ShowKnowledgeBase)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::FilePicker),
        Some(EffectKind::OpenFilePicker)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Attach("notes.md".to_string())),
        Some(EffectKind::AttachKnowledgeBaseSource)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Detach("att-1".to_string())),
        Some(EffectKind::DetachKnowledgeBaseSource)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Reparse("att-1".to_string())),
        Some(EffectKind::ReparseKnowledgeBaseSource)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::AuthLogin(Some("openai headless".to_string()))),
        Some(EffectKind::AuthLogin)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Load(Some(
            "file:///tmp/kuzushi-module.mjs".to_string()
        ))),
        Some(EffectKind::LoadDynamicModule)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Model(Some("openai:gpt-5.5 high".to_string()))),
        Some(EffectKind::PersistGlobalModelSelection)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Pause),
        Some(EffectKind::PauseActiveWork)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Resume(None)),
        Some(EffectKind::ResumeSession)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::SetOption {
            global: true,
            name: "ui.auto_open_activity".to_string(),
            value: "false".to_string(),
        }),
        Some(EffectKind::PersistOptions)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::ThreatRegen),
        Some(EffectKind::Threat)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::ThreatAsk(
            "what changed in the threat model?".to_string()
        )),
        Some(EffectKind::Threat)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Quit),
        Some(EffectKind::Quit)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Demo),
        Some(EffectKind::OfflineDemo)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Replay("latest".to_string())),
        Some(EffectKind::RunArtifact)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Scan(Some(PathBuf::from(".")))),
        Some(EffectKind::OpenGuidedScan)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::ScriptedScan(Some(PathBuf::from(".")))),
        Some(EffectKind::Scan)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Trace("latest".to_string())),
        Some(EffectKind::RunArtifact)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Activity),
        Some(EffectKind::OpenActivity)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Tune),
        Some(EffectKind::RefreshHouseRules)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Target(Some(".".to_string()))),
        Some(EffectKind::ActivateTarget)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Workspace(WorkspaceCommand::Status)),
        Some(EffectKind::ShowWorkspaceStatus)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Component(Some("vendor".to_string()))),
        Some(EffectKind::SelectComponent)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Strategy(StrategyCommand::Approve(
            "review-codeql-scan".to_string()
        ))),
        Some(EffectKind::StrategyStatus)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Strategy(StrategyCommand::Fire)),
        Some(EffectKind::StrategyFire)
    );
    assert_eq!(
        command_effect_kind(ShellCommand::Strategy(StrategyCommand::Correct {
            id: "review-codeql-scan".to_string(),
            to_strategy: "run codeql:scan with authz focus".to_string(),
            reason: Some("tighten authz paths".to_string()),
            scope: StrategyCorrectionCommandScope::Workspace,
        })),
        Some(EffectKind::StrategyCorrection)
    );
}

#[test]
fn command_effect_reducer_routes_stateful_command_families() {
    for command in [
        ShellCommand::PlanApply,
        ShellCommand::PlanDiscard,
        ShellCommand::Back,
        ShellCommand::Backend(None),
        ShellCommand::Config,
        ShellCommand::Cost,
        ShellCommand::BootSplash,
        ShellCommand::Actor(1),
        ShellCommand::Component(None),
        ShellCommand::FailureHandoff,
        ShellCommand::Findings,
        ShellCommand::FindingsFilter("severity:high".to_string()),
        ShellCommand::Health,
        ShellCommand::Help(None),
        ShellCommand::Home,
        ShellCommand::LaunchStartView,
        ShellCommand::LaunchTargetPicker,
        ShellCommand::Logs,
        ShellCommand::Modules,
        ShellCommand::Next,
        ShellCommand::Onboarding,
        ShellCommand::Open("F-0001".to_string()),
        ShellCommand::Options {
            tool: None,
            filter: OptionsFilter::Standard,
        },
        ShellCommand::Permissions,
        ShellCommand::QuitConfirm,
        ShellCommand::ThemePicker,
        ShellCommand::Keymap,
        ShellCommand::UpdateAvailable,
        ShellCommand::Phase(WorkflowPhase::Confirm),
        ShellCommand::Prompts,
        ShellCommand::Prompt("mutate triage \"focus authz\"".to_string()),
        ShellCommand::ProjectModel,
        ShellCommand::Provider(None),
        ShellCommand::Quickstart,
        ShellCommand::RunDiff {
            left: "run-left".to_string(),
            right: "run-right".to_string(),
        },
        ShellCommand::Scene,
        ShellCommand::ShowAliases(None),
        ShellCommand::ShowRuns,
        ShellCommand::Since("HEAD".to_string()),
        ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Toggle)),
        ShellCommand::Tasks,
        ShellCommand::History,
        ShellCommand::Story,
        ShellCommand::Threat(ThreatView::Summary),
        ShellCommand::ThreatEditor,
        ShellCommand::ThreatReject,
        ShellCommand::Tools(None),
        ShellCommand::Tune,
        ShellCommand::Use("sast".to_string()),
        ShellCommand::Workbench(WorkbenchPane::Findings),
        ShellCommand::Strategy(StrategyCommand::Show),
        ShellCommand::Pwn(PwnCommand::Show),
        ShellCommand::Empty,
        ShellCommand::Unknown("wat".to_string()),
        ShellCommand::Workspace(WorkspaceCommand::Unsupported("workspace sync".to_string())),
    ] {
        assert!(
            command_is_effect_routed(command),
            "stateful command family should enter through reduce_command_effects"
        );
    }
}

#[test]
fn findings_command_returns_refresh_then_finalize_effects_without_inline_reload() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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
    app.findings_mut().clear();

    let effects = app
        .reduce_command_effects(&ShellCommand::Findings)
        .expect("findings command is effect-routed");

    assert!(
        app.findings().is_empty(),
        "reload is an effect runtime concern"
    );
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert!(matches!(
        effects.as_slice(),
        [
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: true,
                filter: None
            }),
            ShellEffect::FinalizeWorkbenchOpen(WorkbenchOpenFinalize {
                pane: WorkbenchPane::Findings
            })
        ]
    ));
}

#[test]
fn open_alias_command_returns_refresh_then_open_effect_without_inline_lookup() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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
    app.findings_mut().clear();

    let effects = app
        .reduce_command_effects(&ShellCommand::Open("F-0001".to_string()))
        .expect("open command is effect-routed");

    assert!(
        app.findings().is_empty(),
        "alias lookup stays out of reducer"
    );
    assert!(
        app.selected_finding().is_none(),
        "finding selection happens when the effect executes"
    );
    assert!(matches!(
        effects.as_slice(),
        [
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None
            }),
            ShellEffect::OpenFinding(OpenFindingReference { reference })
        ]
            if reference == "F-0001"
    ));
}

#[test]
fn open_direct_reference_command_skips_alias_refresh() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let effects = app
        .reduce_command_effects(&ShellCommand::Open("abc123".to_string()))
        .expect("open command is effect-routed");

    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::OpenFinding(OpenFindingReference { reference })]
            if reference == "abc123"
    ));
}

#[test]
fn open_finding_lookup_effect_returns_finalize_without_selecting() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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
    EffectRuntime::execute(
        &mut app,
        vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: None,
        })],
    );

    let effects = app.resolve_open_finding_effect(OpenFindingReference {
        reference: "F-0001".to_string(),
    });

    assert!(
        app.selected_finding().is_none(),
        "lookup should not select before the finalizer runs"
    );
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::FinalizeOpenFinding(OpenFindingFinalize {
            reference,
            outcome: OpenFindingOutcome::Found(found)
        })] if reference == "F-0001"
            && found.fingerprint == finding.fingerprint
    ));

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| finding.fingerprint.as_str()),
        Some(finding.fingerprint.as_str())
    );
}

#[test]
fn pwn_show_reducer_returns_refresh_effect_without_reading_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let state_dir = tmp.path().join(".kuzushi/pwn/run-1");
    std::fs::create_dir_all(&state_dir).unwrap();
    let binary = tmp.path().join("challenge-bin");
    std::fs::write(
        state_dir.join("state.json"),
        serde_json::json!({
            "binary": { "path": binary },
            "primitives": [
                { "kind": "ret2win", "confidence": 0.9, "remoteSafe": true }
            ]
        })
        .to_string(),
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app
        .reduce_command_effects(&ShellCommand::Pwn(PwnCommand::Show))
        .expect("pwn command should be effect-routed");

    assert_eq!(app.shell_view(), ShellView::Pwn);
    assert!(app.pwn_view().state_snapshot.is_none());
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], ShellEffect::RefreshPwnState));

    EffectRuntime::execute(&mut app, effects);

    assert!(app.pwn_view().state_snapshot.is_some());
    assert_eq!(app.pwn_view().binary.as_deref(), Some(binary.as_path()));
}

#[test]
fn replay_latest_reducer_defers_latest_pointer_read_to_effect_runtime() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app
        .reduce_command_effects(&ShellCommand::Replay("latest".to_string()))
        .expect("replay command should be effect-routed");

    assert_ne!(app.shell_view(), ShellView::Replay);
    assert!(app.log_lines().iter().all(|line| line.prefix != "error"));
    let open = run_artifact_open(&effects).expect("open run artifact effect");
    assert_eq!(open.selector, "latest");
    assert!(matches!(open.view, RunArtifactView::Replay));
    assert_eq!(open.target.as_deref(), Some(workspace.root()));

    EffectRuntime::execute(&mut app, effects);

    assert_ne!(app.shell_view(), ShellView::Replay);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("could not read latest run pointer")
    }));
}

#[test]
fn activity_command_reducer_defers_session_creation_to_effect_runtime() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let effects = app
        .reduce_command_effects(&ShellCommand::Activity)
        .expect("activity command should be effect-routed");

    let open = activity_open_effect(&effects).expect("open activity effect");
    assert!(open.run_id.is_none());
    assert!(!matches!(app.shell_view(), ShellView::Activity));
    assert!(app.activity().is_none());

    EffectRuntime::execute(&mut app, effects);

    assert!(matches!(app.shell_view(), ShellView::Activity));
    assert!(app.activity().is_some());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "activity" && line.body.contains("dashboard")));
}

#[test]
fn load_command_reducer_defers_dynamic_registry_load_to_effect_runtime() {
    let specifier = "file:///tmp/kuzushi-missing-module.mjs".to_string();
    let mut app = ShellApp::new(V2Config::default(), None);

    let effects = app
        .reduce_command_effects(&ShellCommand::Load(Some(specifier.clone())))
        .expect("load command should be effect-routed");

    let load = dynamic_module_load_effect(&effects).expect("dynamic load effect");
    assert_eq!(load.specifier, specifier);
    assert_eq!(app.shell_view(), ShellView::Tools);
    assert!(app.log_lines().iter().all(|line| line.prefix != "error"));

    EffectRuntime::execute(&mut app, effects);

    assert!(app.log_lines().iter().any(|line| line.prefix == "error"));
}

#[test]
fn clear_command_reducer_defers_conversation_mutation_to_effect_runtime() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    *app.selected_finding_mut() = Some(Finding::new_tool(
        "fixture",
        "clear/finding",
        "src/app.rs",
        12,
        None,
        Severity::High,
        "clear me",
    ));
    app.log("user", "old conversation");

    let effects = app
        .reduce_command_effects(&ShellCommand::Clear)
        .expect("clear command should be effect-routed");

    assert!(has_clear_effect(&effects));
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.selected_finding().is_some());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body == "old conversation"));

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.shell_view(), ShellView::Catalog);
    assert!(app.selected_finding().is_none());
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body == "old conversation"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "system" && line.body.contains("Conversation cleared") }));
}

#[test]
fn workspace_status_reducer_defers_projection_to_effect_runtime() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    let initial_log_len = app.log_len();

    let effects = app
        .reduce_command_effects(&ShellCommand::Workspace(WorkspaceCommand::Status))
        .expect("workspace status command should be effect-routed");

    assert!(has_workspace_status_effect(&effects));
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(app.log_len(), initial_log_len);

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.shell_view(), ShellView::Workspace);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "workspace" && line.body.contains("start shell with --target")
    }));
}

#[test]
fn context_build_reducer_returns_build_effect_without_resolving_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let missing_target = temp.path().join("missing");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(missing_target.clone()));

    let effects = app
        .reduce_command_effects(&ShellCommand::Context(ContextCommand::Build))
        .expect("context build command should be effect-routed");
    let build = context_build_effect(&effects).expect("context build effect");

    assert_eq!(build.target.as_deref(), Some(missing_target.as_path()));
    assert_eq!(build.scope, None);
    assert_ne!(app.shell_view(), ShellView::Context);
    assert_ne!(app.focused_module(), Some("context"));
    assert!(!app.tool_is_running());
    assert!(!app.has_running_work());
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("running context:build")));
}

#[test]
fn pause_resume_reducers_defer_control_token_mutation_to_effect_runtime() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let pause_effects = app
        .reduce_command_effects(&ShellCommand::Pause)
        .expect("pause command should be effect-routed");

    assert!(has_pause_effect(&pause_effects));
    assert!(!cancel.is_paused());
    assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("running"));

    EffectRuntime::execute(&mut app, pause_effects);

    assert!(cancel.is_paused());
    assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("paused"));

    let resume_effects = app
        .reduce_command_effects(&ShellCommand::Resume(None))
        .expect("resume command should be effect-routed");

    let resume = resume_session_effect(&resume_effects).expect("resume effect");
    assert!(resume.run_id.is_none());
    assert!(cancel.is_paused());

    EffectRuntime::execute(&mut app, resume_effects);

    assert!(!cancel.is_paused());
    assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("running"));
}

#[test]
fn terminal_edge_commands_enter_the_command_reducer() {
    let mut app = effect_routed_handler_test_app();

    let empty = app
        .reduce_command_effects(&ShellCommand::Empty)
        .expect("empty command should be reducer-routed");
    assert!(empty.is_empty());

    let scene = app
        .reduce_command_effects(&ShellCommand::Scene)
        .expect("scene command should be reducer-routed");
    assert!(scene.is_empty());
    assert_eq!(app.shell_view(), ShellView::Scene);

    let unknown = app
        .reduce_command_effects(&ShellCommand::Unknown("wat".to_string()))
        .expect("unknown command should be reducer-routed");
    assert!(unknown.is_empty());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "error" && line.body.contains("wat")));

    let unsupported = app
        .reduce_command_effects(&ShellCommand::Workspace(WorkspaceCommand::Unsupported(
            "workspace sync".to_string(),
        )))
        .expect("unsupported workspace command should be reducer-routed");
    assert!(unsupported.is_empty());
    assert_eq!(app.shell_view(), ShellView::Workspace);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("workspace sync is not supported")
    }));
}

#[test]
fn command_effect_reducer_routes_all_fixture_commands() {
    for (label, command) in effect_routed_command_fixtures() {
        assert!(
            command_is_effect_routed(command),
            "{label} should enter through reduce_command_effects"
        );
    }
}

#[test]
fn command_effect_reducer_routes_session_option_commands_without_io_effects() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let effects = app
        .reduce_command_effects(&ShellCommand::SetOption {
            global: false,
            name: "ui.auto_open_activity".to_string(),
            value: "false".to_string(),
        })
        .expect("session option command should be effect-routed");

    assert!(effects.is_empty());
    assert!(!app.ui().auto_open_activity());
}

#[test]
fn command_history_reducer_persists_only_for_workspace_backed_history() {
    let mut targetless_app = ShellApp::new(V2Config::default(), None);
    let targetless_effects = targetless_app.reduce_remember_command("modules");

    assert!(targetless_effects.is_empty());
    assert_eq!(targetless_app.command_history(), ["modules".to_string()]);

    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let history_path = temp.path().join(".kuzushi/v3/shell-history.txt");
    let effects = app.reduce_remember_command("tools");

    assert!(has_history_persist_effect(&effects));
    assert_eq!(app.command_history(), ["tools".to_string()]);
    assert!(!history_path.exists());

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(fs::read_to_string(history_path).unwrap(), "tools");
}

#[test]
fn kb_attachment_reducers_defer_store_mutation_to_effect_runtime() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("notes.md"), "hello\n").unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, ShellCommand::Use("context".to_string()));

    let effects = app
        .reduce_command_effects(&ShellCommand::Attach("notes.md".to_string()))
        .expect("attach command should be effect-routed");
    let attach = kb_attach_effect(&effects).expect("attach effect");

    assert_eq!(attach.source, "notes.md");
    assert!(!workspace
        .root()
        .join(".kuzushi/v3/attachments.json")
        .exists());
    assert!(app.domain().kb_view().attachments.is_empty());
}

#[test]
fn command_effect_reducer_routes_tool_launcher_commands_without_spawning() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    let mut aim_app = ShellApp::new(V2Config::default(), Some(&workspace));
    let aim_effects = aim_app
        .reduce_command_effects(&ShellCommand::Aim(Some("auth".to_string())))
        .expect("aim should be effect-routed");
    let aim_prepare = run_tool_prepare(&aim_effects).expect("aim should prepare a tool");
    assert_eq!(aim_prepare.tool_name, "engagement:aim");
    assert_eq!(
        run_tool_prepare_input(aim_prepare)["focus"],
        serde_json::json!("auth")
    );
    assert_eq!(aim_app.shell_view(), ShellView::Workbench);
    assert!(!aim_app.tool_is_running());
    assert!(!aim_app.jobs().is_running(JobKind::Run));

    let mut recommend_app = ShellApp::new(V2Config::default(), Some(&workspace));
    let recommend_effects = recommend_app
        .reduce_command_effects(&ShellCommand::Recommend)
        .expect("recommend should be effect-routed");
    let recommend_prepare =
        run_tool_prepare(&recommend_effects).expect("recommend should prepare a tool");
    assert_eq!(recommend_prepare.tool_name, "module-recommender:recommend");
    assert_eq!(recommend_app.shell_view(), ShellView::Recommend);
    assert!(!recommend_app.tool_is_running());
    assert!(!recommend_app.jobs().is_running(JobKind::Run));

    let mut patch_app = ShellApp::new(V2Config::default(), Some(&workspace));
    patch_app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "guard tainted input".to_string(),
        side_effect: None,
        diff: "--- a/x.rs\n+++ b/x.rs\n".to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });
    let patch_effects = patch_app
        .reduce_command_effects(&ShellCommand::Patch(PatchCommand::Regen {
            style: Some("minimal".to_string()),
        }))
        .expect("patch regen should be effect-routed");
    let patch_prepare =
        run_tool_prepare(&patch_effects).expect("patch regen should prepare a tool");
    assert_eq!(patch_prepare.tool_name, "patch:finding");
    let patch_input = run_tool_prepare_input(patch_prepare);
    assert_eq!(patch_input["fingerprint"], serde_json::json!("F-0001"));
    assert_eq!(patch_input["style"], serde_json::json!("minimal"));
    assert!(!patch_app.tool_is_running());
    assert!(!patch_app.jobs().is_running(JobKind::Run));
}

#[test]
fn patch_apply_reducer_returns_apply_effect_without_mutating_worktree() {
    let temp = tempfile::tempdir().unwrap();
    let missing_target = temp.path().join("missing");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(missing_target.clone()));
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "guard tainted input".to_string(),
        side_effect: None,
        diff: demo_patch_diff().to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });

    let effects = app
        .reduce_command_effects(&ShellCommand::Patch(PatchCommand::Apply))
        .expect("patch apply should be effect-routed");
    let apply = reviewed_patch_apply(&effects).expect("patch apply effect");

    assert_eq!(apply.alias, "F-0001");
    assert_eq!(apply.diff, demo_patch_diff());
    assert_eq!(apply.target.as_deref(), Some(missing_target.as_path()));
    assert!(app.engagement.pending_patch().is_some());
    assert_ne!(app.router.workbench().page(), Some(WorkbenchPage::Ship));
    assert!(
        !app.log_lines()
            .iter()
            .any(|line| line.prefix == "error"
                && line.body.contains("target <path> then patch apply"))
    );
}

#[test]
fn patch_reject_reducer_discards_pending_patch_without_effects() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "guard tainted input".to_string(),
        side_effect: None,
        diff: demo_patch_diff().to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });

    let effects = app
        .reduce_command_effects(&ShellCommand::Patch(PatchCommand::Reject))
        .expect("patch reject should be reducer-owned");

    assert!(effects.is_empty());
    assert!(app.engagement.pending_patch().is_none());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Ship));
}

#[cfg(unix)]
#[test]
fn patch_apply_effect_applies_reviewed_diff_and_updates_view_state() {
    if git_is_unavailable() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().to_path_buf();
    fs::write(repo.join("demo.txt"), "before\n").unwrap();
    init_git_repo(&repo);
    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "guard tainted input".to_string(),
        side_effect: None,
        diff: demo_patch_diff().to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });

    let effects = app
        .reduce_command_effects(&ShellCommand::Patch(PatchCommand::Apply))
        .expect("patch apply should be effect-routed");
    EffectRuntime::execute(&mut app, effects);

    assert_eq!(
        fs::read_to_string(repo.join("demo.txt")).unwrap(),
        "after\n"
    );
    assert!(app.engagement.pending_patch().is_none());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Ship));
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "patch" && line.body.contains("demo.txt")));
}

#[test]
fn threat_apply_reducer_returns_apply_effect_without_writing_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().to_path_buf();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.clone()));
    app.set_pending_threat_patch(ThreatPatch {
        goal: "g".to_string(),
        summary: "s".to_string(),
        patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
        unsupported: vec!["manual follow-up".to_string()],
    });

    let effects = app
        .reduce_command_effects(&ShellCommand::ThreatApply)
        .expect("threat apply should be effect-routed");
    let apply = threat_patch_apply(&effects).expect("threat apply effect");

    assert_eq!(apply.target.as_deref(), Some(target.as_path()));
    assert_eq!(
        apply.patch.patch.pointer("/trustZones/admin"),
        Some(&serde_json::json!("isolated"))
    );
    assert!(app.engagement.has_pending_threat_patch());
    assert!(load_persistent_threat_model(&target).is_none());
}

#[test]
fn review_decision_reducer_returns_record_effect_without_writing_store() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    *app.findings_mut() = vec![Finding::new_tool(
        "fixture",
        "fixture/open",
        "src/app.ts",
        7,
        None,
        Severity::High,
        "open finding",
    )];
    let db_existed_before = workspace.findings_db_path().exists();

    let effects = app
        .reduce_command_effects(&ShellCommand::ReviewDecision(
            ReviewDecisionCommand::Record {
                verdict: "suppressed".to_string(),
                reason: "reviewed under approved suppression policy".to_string(),
            },
        ))
        .expect("review decision should be effect-routed");
    let apply = review_decision_apply(&effects).expect("review decision effect");

    assert_eq!(apply.target.as_deref(), Some(workspace.root()));
    assert_eq!(
        apply.decision.verdict,
        kuzushi_core::findings::ReviewDecisionVerdict::Suppressed
    );
    assert_eq!(
        apply.decision.rationale,
        "reviewed under approved suppression policy"
    );
    assert_eq!(apply.finding.title, "open finding");
    assert_eq!(
        workspace.findings_db_path().exists(),
        db_existed_before,
        "reducer must not create the findings store"
    );
}

#[test]
fn workspace_reducers_return_file_effects_without_writing_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let export_path = temp.path().join("findings.json");

    let export_effects = app
        .reduce_command_effects(&ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: export_path.clone(),
            format: Some("json".to_string()),
            completeness: Some("open".to_string()),
            allow_empty: true,
        }))
        .expect("workspace export should be effect-routed");
    let export = workspace_export_effect(&export_effects).expect("workspace export effect");

    assert_eq!(export.output, export_path);
    assert_eq!(export.format.as_deref(), Some("json"));
    assert_eq!(export.completeness.as_deref(), Some("open"));
    assert!(export.allow_empty);
    assert_eq!(export.target.as_deref(), Some(workspace.root()));
    assert!(!export.output.exists());

    let scope_effects = app
        .reduce_command_effects(&ShellCommand::Workspace(WorkspaceCommand::ScopeInit))
        .expect("workspace scope init should be effect-routed");
    let scope = workspace_scope_init_effect(&scope_effects).expect("scope init effect");

    assert_eq!(scope.target.as_deref(), Some(workspace.root()));
    assert!(!temp.path().join(".kuzushi/scope.toml").exists());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectKind {
    ActivateTarget,
    AdvancePrereqChain,
    OpenActivity,
    ApplyReviewedPatch,
    ApplySastTaskOptions,
    ApplyThreatPatch,
    AuthLogin,
    AbortForBudget,
    AttachKnowledgeBaseSource,
    Agent,
    Cancel,
    ClearConversation,
    BuildContext,
    ContinuePastBudget,
    DetachKnowledgeBaseSource,
    DiffPromptOverride,
    DispatchNextPlanningTask,
    RefreshDeterministicRecommendations,
    EditPromptOverride,
    ListPromptOverrides,
    LoadDynamicModule,
    OfflineDemo,
    OpenFilePicker,
    OpenGuidedScan,
    PauseActiveWork,
    PersistCommandHistory,
    PersistGlobalModelSelection,
    PersistPlanningOptionOverride,
    PersistOptions,
    Planner,
    Quit,
    RequestExitAbort,
    RequestShellQuit,
    FinishShellQuit,
    ResetPromptOverride,
    ResetHouseRules,
    ReparseKnowledgeBaseSource,
    RefreshContextView,
    RefreshFindings,
    RefreshHouseRules,
    ReportFilteredFindingMovement,
    FinalizeGuidedScanOpen,
    FinalizeWorkbenchOpen,
    FinalizeOpenFinding,
    FinalizeSastTaskCommand,
    HydrateSceneSnapshots,
    FinalizeScanCompletion,
    RefreshPwnState,
    RefreshProgramScope,
    RecordAgentRun,
    RecordPromptMutation,
    RecordScanRun,
    RecordScanStageTrace,
    RecordToolRun,
    RecordReviewDecision,
    ResumeSession,
    OpenFinding,
    RunArtifact,
    RunTool,
    Scan,
    SelectComponent,
    SessionEnv,
    StrategyCorrection,
    StrategyFire,
    StrategyStatus,
    ShowAuthStatus,
    ShowContextStatus,
    ShowKnowledgeBase,
    ShowHouseRules,
    ShowPromptOverride,
    ShowWorkspaceStatus,
    SwitchTargetRevision,
    Threat,
    UpdatePromptMutationStatus,
    WaitForAbortCleanup,
    WorkspaceExport,
    WorkspaceScope,
    WriteHouseRules,
    WritePromptOverride,
}

fn command_effect_kind(command: ShellCommand) -> Option<EffectKind> {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);
    let effect = app.reduce_command_effects(&command)?.into_iter().next()?;
    Some(match effect {
        ShellEffect::ApplyReviewedPatch(_) => EffectKind::ApplyReviewedPatch,
        ShellEffect::ApplySastTaskOptions(_) => EffectKind::ApplySastTaskOptions,
        ShellEffect::ApplyThreatPatch(_) => EffectKind::ApplyThreatPatch,
        ShellEffect::AttachKnowledgeBaseSource(_) => EffectKind::AttachKnowledgeBaseSource,
        ShellEffect::AuthLogin(_) => EffectKind::AuthLogin,
        ShellEffect::ActivateTarget(_) => EffectKind::ActivateTarget,
        ShellEffect::AdvancePrereqChain(_) => EffectKind::AdvancePrereqChain,
        ShellEffect::AbortForBudget => EffectKind::AbortForBudget,
        ShellEffect::CancelActiveJobs => EffectKind::Cancel,
        ShellEffect::CancelJob(_) => EffectKind::Cancel,
        ShellEffect::ClearConversation => EffectKind::ClearConversation,
        ShellEffect::BuildContext(_) => EffectKind::BuildContext,
        ShellEffect::ContinuePastBudget => EffectKind::ContinuePastBudget,
        ShellEffect::DetachKnowledgeBaseSource(_) => EffectKind::DetachKnowledgeBaseSource,
        ShellEffect::OpenActivity(_) => EffectKind::OpenActivity,
        ShellEffect::DispatchAgent(_) => EffectKind::Agent,
        ShellEffect::DispatchNextPlanningTask(_) => EffectKind::DispatchNextPlanningTask,
        ShellEffect::RefreshDeterministicRecommendations(_) => {
            EffectKind::RefreshDeterministicRecommendations
        }
        ShellEffect::PrepareRunTool(_) => EffectKind::RunTool,
        ShellEffect::DispatchRunTool(_) => EffectKind::RunTool,
        ShellEffect::DiffPromptOverride(_) => EffectKind::DiffPromptOverride,
        ShellEffect::EditPromptOverride(_) => EffectKind::EditPromptOverride,
        ShellEffect::ListPromptOverrides(_) => EffectKind::ListPromptOverrides,
        ShellEffect::LoadDynamicModule(_) => EffectKind::LoadDynamicModule,
        ShellEffect::OpenFilePicker => EffectKind::OpenFilePicker,
        ShellEffect::OpenGuidedScan(_) => EffectKind::OpenGuidedScan,
        ShellEffect::PauseActiveWork => EffectKind::PauseActiveWork,
        ShellEffect::PersistCommandHistory => EffectKind::PersistCommandHistory,
        ShellEffect::PersistGlobalModelSelection(_) => EffectKind::PersistGlobalModelSelection,
        ShellEffect::PersistPlanningOptionOverride(_) => EffectKind::PersistPlanningOptionOverride,
        ShellEffect::PersistOptions(_) => EffectKind::PersistOptions,
        ShellEffect::ResetPromptOverride(_) => EffectKind::ResetPromptOverride,
        ShellEffect::ResumeSession(_) => EffectKind::ResumeSession,
        ShellEffect::RequestExitAbort => EffectKind::RequestExitAbort,
        ShellEffect::RequestShellQuit => EffectKind::RequestShellQuit,
        ShellEffect::Quit => EffectKind::Quit,
        ShellEffect::FinishShellQuit => EffectKind::FinishShellQuit,
        ShellEffect::RecordAgentRun(_) => EffectKind::RecordAgentRun,
        ShellEffect::RecordPromptMutation(_) => EffectKind::RecordPromptMutation,
        ShellEffect::RecordScanRun(_) => EffectKind::RecordScanRun,
        ShellEffect::RecordScanStageTrace(_) => EffectKind::RecordScanStageTrace,
        ShellEffect::RecordToolRun(_) => EffectKind::RecordToolRun,
        ShellEffect::RecordReviewDecision(_) => EffectKind::RecordReviewDecision,
        ShellEffect::ResetHouseRules(_) => EffectKind::ResetHouseRules,
        ShellEffect::ReparseKnowledgeBaseSource(_) => EffectKind::ReparseKnowledgeBaseSource,
        ShellEffect::RefreshContextView => EffectKind::RefreshContextView,
        ShellEffect::RefreshFindings(_) => EffectKind::RefreshFindings,
        ShellEffect::RefreshHouseRules(_) => EffectKind::RefreshHouseRules,
        ShellEffect::ReportFilteredFindingMovement(_) => EffectKind::ReportFilteredFindingMovement,
        ShellEffect::FinalizeGuidedScanOpen => EffectKind::FinalizeGuidedScanOpen,
        ShellEffect::FinalizeWorkbenchOpen(_) => EffectKind::FinalizeWorkbenchOpen,
        ShellEffect::FinalizeOpenFinding(_) => EffectKind::FinalizeOpenFinding,
        ShellEffect::FinalizeSastTaskCommand(_) => EffectKind::FinalizeSastTaskCommand,
        ShellEffect::HydrateSceneSnapshots(_) => EffectKind::HydrateSceneSnapshots,
        ShellEffect::FinalizeScanCompletion(_) => EffectKind::FinalizeScanCompletion,
        ShellEffect::RefreshPwnState => EffectKind::RefreshPwnState,
        ShellEffect::RefreshProgramScope => EffectKind::RefreshProgramScope,
        ShellEffect::OpenFinding(_) => EffectKind::OpenFinding,
        ShellEffect::OpenRunArtifact(_) => EffectKind::RunArtifact,
        ShellEffect::SelectComponent(_) => EffectKind::SelectComponent,
        ShellEffect::FireNextApprovedStrategy(_) => EffectKind::StrategyFire,
        ShellEffect::RecordStrategyCorrection(_) => EffectKind::StrategyCorrection,
        ShellEffect::UpdateStrategyProposalStatus(_) => EffectKind::StrategyStatus,
        ShellEffect::SetSessionEnv(_) => EffectKind::SessionEnv,
        ShellEffect::ShowAuthStatus(_) => EffectKind::ShowAuthStatus,
        ShellEffect::ShowContextStatus => EffectKind::ShowContextStatus,
        ShellEffect::ShowKnowledgeBase(_) => EffectKind::ShowKnowledgeBase,
        ShellEffect::ShowHouseRules(_) => EffectKind::ShowHouseRules,
        ShellEffect::ShowPromptOverride(_) => EffectKind::ShowPromptOverride,
        ShellEffect::ShowWorkspaceStatus => EffectKind::ShowWorkspaceStatus,
        ShellEffect::StartOfflineDemoFixtureScan => EffectKind::OfflineDemo,
        ShellEffect::StartPlanner(_) => EffectKind::Planner,
        ShellEffect::PrepareScan(_) => EffectKind::Scan,
        ShellEffect::StartScan(_) => EffectKind::Scan,
        ShellEffect::StartThreat(_) => EffectKind::Threat,
        ShellEffect::SwitchTargetRevision(_) => EffectKind::SwitchTargetRevision,
        ShellEffect::UpdatePromptMutationStatus(_) => EffectKind::UpdatePromptMutationStatus,
        ShellEffect::WaitForAbortCleanup => EffectKind::WaitForAbortCleanup,
        ShellEffect::WorkspaceExportFindings(_) => EffectKind::WorkspaceExport,
        ShellEffect::WorkspaceScopeInit(_) => EffectKind::WorkspaceScope,
        ShellEffect::WriteHouseRules(_) => EffectKind::WriteHouseRules,
        ShellEffect::WritePromptOverride(_) => EffectKind::WritePromptOverride,
    })
}

fn command_is_effect_routed(command: ShellCommand) -> bool {
    let mut app = effect_routed_handler_test_app();
    app.reduce_command_effects(&command).is_some()
}

fn effect_routed_command_fixtures() -> Vec<(&'static str, ShellCommand)> {
    vec![
        ("cancel", ShellCommand::Cancel),
        ("clear", ShellCommand::Clear),
        ("back", ShellCommand::Back),
        ("backend", ShellCommand::Backend(None)),
        ("config", ShellCommand::Config),
        ("cost", ShellCommand::Cost),
        ("boot-splash", ShellCommand::BootSplash),
        ("actor", ShellCommand::Actor(1)),
        ("component", ShellCommand::Component(None)),
        ("failure-handoff", ShellCommand::FailureHandoff),
        ("findings", ShellCommand::Findings),
        (
            "findings-filter",
            ShellCommand::FindingsFilter("severity:high".to_string()),
        ),
        ("health", ShellCommand::Health),
        ("help", ShellCommand::Help(None)),
        ("home", ShellCommand::Home),
        ("launch-start-view", ShellCommand::LaunchStartView),
        ("launch-target-picker", ShellCommand::LaunchTargetPicker),
        ("logs", ShellCommand::Logs),
        ("modules", ShellCommand::Modules),
        ("next", ShellCommand::Next),
        ("onboarding", ShellCommand::Onboarding),
        ("open", ShellCommand::Open("F-0001".to_string())),
        (
            "options",
            ShellCommand::Options {
                tool: None,
                filter: OptionsFilter::Standard,
            },
        ),
        (
            "context-status",
            ShellCommand::Context(ContextCommand::Status),
        ),
        (
            "context-build",
            ShellCommand::Context(ContextCommand::Build),
        ),
        (
            "knowledge-base",
            ShellCommand::KnowledgeBase(Some("context".to_string())),
        ),
        ("file-picker", ShellCommand::FilePicker),
        ("attach", ShellCommand::Attach("notes.md".to_string())),
        ("detach", ShellCommand::Detach("att-1".to_string())),
        ("history", ShellCommand::History),
        ("permissions", ShellCommand::Permissions),
        ("quit-confirm", ShellCommand::QuitConfirm),
        ("theme-picker", ShellCommand::ThemePicker),
        ("keymap", ShellCommand::Keymap),
        ("update-available", ShellCommand::UpdateAvailable),
        ("phase", ShellCommand::Phase(WorkflowPhase::Confirm)),
        ("prompts", ShellCommand::Prompts),
        (
            "prompt",
            ShellCommand::Prompt("mutate triage \"focus authz\"".to_string()),
        ),
        ("provider", ShellCommand::Provider(None)),
        ("project-model", ShellCommand::ProjectModel),
        ("quickstart", ShellCommand::Quickstart),
        (
            "run-diff",
            ShellCommand::RunDiff {
                left: "run-left".to_string(),
                right: "run-right".to_string(),
            },
        ),
        ("show-aliases", ShellCommand::ShowAliases(None)),
        ("show-runs", ShellCommand::ShowRuns),
        ("scene", ShellCommand::Scene),
        ("since", ShellCommand::Since("HEAD".to_string())),
        (
            "task",
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Toggle)),
        ),
        ("tasks", ShellCommand::Tasks),
        ("story", ShellCommand::Story),
        ("threat", ShellCommand::Threat(ThreatView::Summary)),
        ("threat-editor", ShellCommand::ThreatEditor),
        ("threat-reject", ShellCommand::ThreatReject),
        ("tools", ShellCommand::Tools(None)),
        ("tune", ShellCommand::Tune),
        ("use", ShellCommand::Use("sast".to_string())),
        (
            "workbench",
            ShellCommand::Workbench(WorkbenchPane::Findings),
        ),
        ("demo", ShellCommand::Demo),
        ("recommend", ShellCommand::Recommend),
        ("aim", ShellCommand::Aim(Some("auth".to_string()))),
        (
            "run-tool",
            ShellCommand::RunTool {
                tool: Some("semgrep:scan".to_string()),
                input: None,
            },
        ),
        ("ask", ShellCommand::Ask("What next?".to_string())),
        (
            "load",
            ShellCommand::Load(Some("file:///tmp/kuzushi-module.mjs".to_string())),
        ),
        ("pause", ShellCommand::Pause),
        ("plan", ShellCommand::Plan("map authz drift".to_string())),
        ("plan-apply", ShellCommand::PlanApply),
        ("plan-discard", ShellCommand::PlanDiscard),
        ("scan", ShellCommand::Scan(Some(PathBuf::from(".")))),
        (
            "set-option",
            ShellCommand::SetOption {
                global: true,
                name: "ui.auto_open_activity".to_string(),
                value: "false".to_string(),
            },
        ),
        (
            "unset-option",
            ShellCommand::UnsetOption {
                global: true,
                name: "ui.auto_open_activity".to_string(),
            },
        ),
        ("threat-regen", ShellCommand::ThreatRegen),
        (
            "threat-ask",
            ShellCommand::ThreatAsk("what changed?".to_string()),
        ),
        ("threat-apply", ShellCommand::ThreatApply),
        (
            "review-decision",
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
                verdict: "needs_review".to_string(),
                reason: "needs more evidence".to_string(),
            }),
        ),
        ("strategy", ShellCommand::Strategy(StrategyCommand::Show)),
        (
            "strategy-approve",
            ShellCommand::Strategy(StrategyCommand::Approve("review-codeql-scan".to_string())),
        ),
        (
            "strategy-fire",
            ShellCommand::Strategy(StrategyCommand::Fire),
        ),
        (
            "strategy-correct",
            ShellCommand::Strategy(StrategyCommand::Correct {
                id: "review-codeql-scan".to_string(),
                to_strategy: "run codeql:scan with authz focus".to_string(),
                reason: Some("tighten authz paths".to_string()),
                scope: StrategyCorrectionCommandScope::Workspace,
            }),
        ),
        ("pwn", ShellCommand::Pwn(PwnCommand::Show)),
        ("activity", ShellCommand::Activity),
        ("replay", ShellCommand::Replay("latest".to_string())),
        ("resume", ShellCommand::Resume(None)),
        ("trace", ShellCommand::Trace("latest".to_string())),
        ("target", ShellCommand::Target(Some(".".to_string()))),
        (
            "target-revision",
            ShellCommand::TargetRevision("HEAD".to_string()),
        ),
        ("reparse", ShellCommand::Reparse("att-1".to_string())),
        (
            "workspace-status",
            ShellCommand::Workspace(WorkspaceCommand::Status),
        ),
        (
            "workspace-scope-init",
            ShellCommand::Workspace(WorkspaceCommand::ScopeInit),
        ),
        (
            "workspace-export",
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("/tmp/kuzushi-findings.json"),
                format: Some("json".to_string()),
                completeness: None,
                allow_empty: true,
            }),
        ),
        (
            "workspace-unsupported",
            ShellCommand::Workspace(WorkspaceCommand::Unsupported("workspace sync".to_string())),
        ),
        ("empty", ShellCommand::Empty),
        ("unknown", ShellCommand::Unknown("wat".to_string())),
        ("quit", ShellCommand::Quit),
    ]
}

fn effect_routed_handler_test_app() -> ShellApp {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    ShellApp::new(config, None)
}

fn persist_option_scope(effects: &[ShellEffect]) -> Option<OptionScope> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::PersistOptions(scope) => Some(*scope),
        _ => None,
    })
}

fn has_history_persist_effect(effects: &[ShellEffect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::PersistCommandHistory))
}

fn has_pause_effect(effects: &[ShellEffect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::PauseActiveWork))
}

fn has_clear_effect(effects: &[ShellEffect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::ClearConversation))
}

fn has_workspace_status_effect(effects: &[ShellEffect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::ShowWorkspaceStatus))
}

fn kb_attach_effect(effects: &[ShellEffect]) -> Option<&KnowledgeBaseAttach> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::AttachKnowledgeBaseSource(attach) => Some(attach),
        _ => None,
    })
}

fn resume_session_effect(effects: &[ShellEffect]) -> Option<&ResumeSession> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ResumeSession(resume) => Some(resume),
        _ => None,
    })
}

fn run_artifact_open(effects: &[ShellEffect]) -> Option<&OpenRunArtifact> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::OpenRunArtifact(open) => Some(open),
        _ => None,
    })
}

fn activity_open_effect(effects: &[ShellEffect]) -> Option<&ActivityOpen> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::OpenActivity(open) => Some(open),
        _ => None,
    })
}

fn dynamic_module_load_effect(effects: &[ShellEffect]) -> Option<&DynamicModuleLoad> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::LoadDynamicModule(load) => Some(load),
        _ => None,
    })
}

fn target_activation_effect(effects: &[ShellEffect]) -> Option<&TargetActivation> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ActivateTarget(activation) => Some(activation),
        _ => None,
    })
}

fn target_revision_switch_effect(effects: &[ShellEffect]) -> Option<&TargetRevisionSwitch> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::SwitchTargetRevision(switch) => Some(switch),
        _ => None,
    })
}

fn silent_findings_refresh_effect(effects: &[ShellEffect]) -> bool {
    effects.iter().any(|effect| {
        matches!(
            effect,
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None
            })
        )
    })
}

fn filtered_findings_refresh_effect(effects: &[ShellEffect]) -> Option<&str> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::RefreshFindings(FindingsRefresh {
            announce: true,
            filter: Some(expression),
        }) => Some(expression.as_str()),
        _ => None,
    })
}

fn program_scope_refresh_effect(effects: &[ShellEffect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::RefreshProgramScope))
}

fn run_tool_launch(effects: &[ShellEffect]) -> Option<&RunToolLaunch> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::DispatchRunTool(launch) => Some(launch),
        _ => None,
    })
}

fn run_tool_prepare(effects: &[ShellEffect]) -> Option<&RunToolPreparation> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::PrepareRunTool(prepare) => Some(prepare),
        _ => None,
    })
}

fn run_tool_prepare_input(prepare: &RunToolPreparation) -> serde_json::Value {
    let raw = prepare.input.as_deref().unwrap_or("{}");
    serde_json::from_str(raw).expect("run tool prepare input should be JSON")
}

fn scan_prepare(effects: &[ShellEffect]) -> Option<&ScanStartPreparation> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::PrepareScan(prepare) => Some(prepare),
        _ => None,
    })
}

fn context_build_effect(effects: &[ShellEffect]) -> Option<&ContextBuild> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::BuildContext(build) => Some(build),
        _ => None,
    })
}

fn reviewed_patch_apply(effects: &[ShellEffect]) -> Option<&ReviewedPatchApply> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ApplyReviewedPatch(apply) => Some(apply),
        _ => None,
    })
}

fn threat_patch_apply(effects: &[ShellEffect]) -> Option<&ThreatPatchApply> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ApplyThreatPatch(apply) => Some(apply),
        _ => None,
    })
}

fn review_decision_apply(effects: &[ShellEffect]) -> Option<&ReviewDecisionApply> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::RecordReviewDecision(apply) => Some(apply),
        _ => None,
    })
}

fn review_decision_apply_owned(effects: Vec<ShellEffect>) -> Option<ReviewDecisionApply> {
    effects.into_iter().find_map(|effect| match effect {
        ShellEffect::RecordReviewDecision(apply) => Some(apply),
        _ => None,
    })
}

fn workspace_export_effect(effects: &[ShellEffect]) -> Option<&WorkspaceExportFindings> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::WorkspaceExportFindings(export) => Some(export),
        _ => None,
    })
}

fn workspace_scope_init_effect(effects: &[ShellEffect]) -> Option<&WorkspaceScopeInit> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::WorkspaceScopeInit(init) => Some(init),
        _ => None,
    })
}

fn house_rules_write_effect(effects: &[ShellEffect]) -> Option<&HouseRulesWrite> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::WriteHouseRules(write) => Some(write),
        _ => None,
    })
}

fn house_rules_reset_effect(effects: &[ShellEffect]) -> Option<&HouseRulesReset> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ResetHouseRules(reset) => Some(reset),
        _ => None,
    })
}

fn house_rules_show_effect(effects: &[ShellEffect]) -> Option<&HouseRulesShow> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ShowHouseRules(show) => Some(show),
        _ => None,
    })
}

fn prompt_override_write_effect(effects: &[ShellEffect]) -> Option<&PromptOverrideWrite> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::WritePromptOverride(write) => Some(write),
        _ => None,
    })
}

fn prompt_override_edit_effect(effects: &[ShellEffect]) -> Option<&PromptOverrideEdit> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::EditPromptOverride(edit) => Some(edit),
        _ => None,
    })
}

fn auth_status_show_effect(effects: &[ShellEffect]) -> Option<&AuthStatusShow> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ShowAuthStatus(show) => Some(show),
        _ => None,
    })
}

fn auth_login_effect(effects: &[ShellEffect]) -> Option<&AuthLoginStart> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::AuthLogin(login) => Some(login),
        _ => None,
    })
}

fn global_model_persist_effect(effects: &[ShellEffect]) -> Option<&GlobalModelSelectionPersist> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::PersistGlobalModelSelection(selection) => Some(selection),
        _ => None,
    })
}

fn prompt_override_reset_effect(effects: &[ShellEffect]) -> Option<&PromptOverrideReset> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ResetPromptOverride(reset) => Some(reset),
        _ => None,
    })
}

fn prompt_override_show_effect(effects: &[ShellEffect]) -> Option<&PromptOverrideShow> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ShowPromptOverride(show) => Some(show),
        _ => None,
    })
}

fn prompt_override_diff_effect(effects: &[ShellEffect]) -> Option<&PromptOverrideDiff> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::DiffPromptOverride(diff) => Some(diff),
        _ => None,
    })
}

fn prompt_override_list_effect(effects: &[ShellEffect]) -> Option<&PromptOverrideList> {
    effects.iter().find_map(|effect| match effect {
        ShellEffect::ListPromptOverrides(list) => Some(list),
        _ => None,
    })
}

fn demo_patch_diff() -> &'static str {
    "diff --git a/demo.txt b/demo.txt\n\
     --- a/demo.txt\n\
     +++ b/demo.txt\n\
     @@ -1 +1 @@\n\
     -before\n\
     +after\n"
}

#[test]
fn tools_command_applies_filter() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Tools(Some("semgrep".to_string())));

    assert_eq!(app.shell_view(), ShellView::Tools);
    assert_eq!(app.router.tools().filter(), Some("semgrep"));
    assert_eq!(app.router.tools().scroll(), 0);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "tool" && line.body.contains("matching \"semgrep\"")));
}

#[test]
fn findings_command_loads_store_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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
    run_command(&mut app, ShellCommand::Findings);

    assert_eq!(app.findings().len(), 1);
    // `findings` now lands on the Workbench command center (FINDINGS pane).
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn open_command_accepts_deterministic_finding_alias() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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
    run_command(&mut app, ShellCommand::Open("F-0001".to_string()));

    // A selected finding now reads in the Workbench DETAILS pane.
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
    assert_eq!(
        app.selected_finding()
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
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let mut stable_first = make_finding(Severity::High, "aaaa1111", "stable first");
    let stable_later = make_finding(Severity::High, "zzzz1111", "stored later");
    stable_first.file_path = "src/a.rs".to_string();
    store.insert_finding("run-1", &stable_first).unwrap();
    store.insert_finding("run-1", &stable_later).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, ShellCommand::Open("F-0001".to_string()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(
        app.selected_finding()
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
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let stable_first = make_finding(Severity::High, "aaaa1111", "stable first");
    let stored_later = make_finding(Severity::High, "zzzz1111", "stored later");
    store.insert_finding("run-1", &stable_first).unwrap();
    store.insert_finding("run-1", &stored_later).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.findings_mut().clear();
    app.set_scan_panel(Some(ScanPanelState {
        run_id: None,
        target: workspace.root().to_path_buf(),
        stage: "running scan".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_activity(Some(ActivitySession::new("scan-pending")));
    let effects = app.apply_scan_event(ScanEvent::Finished {
        run_id: "run-1".to_string(),
        findings_count: 2,
        cost_usd: None,
    });

    assert!(!app.log_lines().iter().any(|line| {
        line.prefix == "scan" && line.body.contains("top alias F-0001 -> aaaa1111")
    }));
    assert!(
        app.findings().is_empty(),
        "findings refresh should be effect-driven"
    );
    assert_eq!(
        app.activity().map(|session| session.run_id.as_str()),
        Some("run-1")
    );
    let events_path = kuzushi_core::run_dir(workspace.root(), "run-1").join("events.jsonl");
    assert!(!events_path.exists());
    EffectRuntime::execute(&mut app, effects);

    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "scan" && line.body.contains("top alias F-0001 -> aaaa1111")
    }));
    assert!(app.log_lines().iter().any(
        |line| line.prefix == "result" && line.body == "fail (2 findings / 2 high) exit_hint=1"
    ));
    assert_eq!(
        kuzushi_core::stable_finding_alias(app.findings(), "aaaa1111").as_deref(),
        Some("F-0001")
    );
    let events = fs::read_to_string(events_path).unwrap();
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
    run_command(&mut app, ShellCommand::Use("dep-hygiene".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: None,
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(
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
    run_command(&mut app, ShellCommand::Use("context".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"sampleLimit":10}"#.to_string()),
        },
    );

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.has_running_work());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "tool" && line.body.contains("running context:build in background")
    }));
    drain_tool(&mut app);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "result" && line.body.contains("context:build indexed 2 files")
    }));
    assert!(app.domain().context_view().exists);
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
    run_command(&mut app, parse_command("use context"));
    run_command(&mut app, parse_command(r#"run . {"sampleLimit":10}"#));

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.has_running_work());
    drain_tool(&mut app);
    assert!(app.domain().context_view().exists);
    assert!(app.log_lines().iter().any(|line| {
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

    run_command(&mut app, ShellCommand::Context(ContextCommand::Build));

    // Auto-open lifts the user into the Activity view so the live trace
    // feed is visible while context:build runs. The original test
    // contract (shell_view == Context after dispatch) is now superseded.
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(app.focused_module(), Some("context"));
    assert!(app.has_running_work());
    drain_tool(&mut app);
    assert!(app.domain().context_view().exists);
    assert!(
        app.log_lines()
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

    run_command(&mut app, ShellCommand::Context(ContextCommand::Status));

    assert_eq!(app.shell_view(), ShellView::Context);
    assert!(!app.domain().context_view().exists);
    assert!(app.domain().context_view().status.contains("missing"));

    run_command(&mut app, ShellCommand::Context(ContextCommand::Build));
    drain_tool(&mut app);
    run_command(&mut app, ShellCommand::Context(ContextCommand::Show));

    assert!(app.domain().context_view().exists);
    assert!(app
        .domain()
        .context_view()
        .status
        .contains("snapshot present"));
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

    run_command(
        &mut app,
        ShellCommand::Context(ContextCommand::Regen("routes".to_string())),
    );

    let error = app
        .log_lines()
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

    run_command(&mut app, ShellCommand::Workspace(WorkspaceCommand::Status));

    assert_eq!(app.shell_view(), ShellView::Workspace);
    assert_eq!(app.domain().workspace_view().root, None);
    assert!(app
        .domain()
        .workspace_view()
        .status
        .contains("no active workspace"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "workspace" && line.body.contains("start shell with --target")));
}

#[test]
fn strategy_approve_command_updates_persisted_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut proposal = kuzushi_core::StrategyProposal::new(
        kuzushi_core::StrategyPhase::Review,
        "run codeql:scan",
        "language coverage is present",
    );
    proposal.id = "review-codeql-scan".to_string();
    kuzushi_core::append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        parse_command("strategy approve review-codeql-scan"),
    );

    assert_eq!(app.shell_view(), ShellView::StrategyQueue);
    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].status,
        kuzushi_core::StrategyProposalStatus::Approved
    );
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.prefix == "strategy"
                && line.body.contains("approved review-codeql-scan"))
    );
}

#[test]
fn strategy_approve_reducer_returns_effect_without_persisting_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut proposal = kuzushi_core::StrategyProposal::new(
        kuzushi_core::StrategyPhase::Review,
        "run codeql:scan",
        "language coverage is present",
    );
    proposal.id = "review-codeql-scan".to_string();
    kuzushi_core::append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects =
        app.reduce_strategy_command(&StrategyCommand::Approve("review-codeql-scan".to_string()));

    assert_eq!(app.shell_view(), ShellView::StrategyQueue);
    let [ShellEffect::UpdateStrategyProposalStatus(update)] = effects.as_slice() else {
        panic!("strategy approve should return a status update effect");
    };
    assert_eq!(update.target.as_deref(), Some(workspace.root()));
    assert_eq!(update.id, "review-codeql-scan");
    assert_eq!(
        update.status,
        kuzushi_core::StrategyProposalStatus::Approved
    );
    assert_eq!(update.label, "approved");
    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].status,
        kuzushi_core::StrategyProposalStatus::Proposed
    );

    EffectRuntime::execute(&mut app, effects);

    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].status,
        kuzushi_core::StrategyProposalStatus::Approved
    );
}

#[test]
fn strategy_fire_runs_next_approved_runnable_proposal() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut proposal = kuzushi_core::StrategyProposal::new(
        kuzushi_core::StrategyPhase::Review,
        "show workspace status",
        "cheap readiness check",
    )
    .with_tool("workspace:status", Some(serde_json::json!({})))
    .with_preflight(kuzushi_core::StrategyPreflight::ready())
    .with_estimates(
        Some(0.0),
        Some("instant".to_string()),
        kuzushi_core::StrategyResourceRisk::Low,
    );
    proposal.id = "review-workspace-status".to_string();
    proposal.status = kuzushi_core::StrategyProposalStatus::Approved;
    kuzushi_core::append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(&mut app, parse_command("strategy fire"));

    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].status,
        kuzushi_core::StrategyProposalStatus::Running
    );
    assert_eq!(app.running_tool_name(), Some("workspace:status"));
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| line.prefix == "strategy"
        && line
            .body
            .contains("firing review-workspace-status via workspace:status")));
}

#[test]
fn strategy_fire_reducer_returns_effect_without_marking_running() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut proposal = kuzushi_core::StrategyProposal::new(
        kuzushi_core::StrategyPhase::Review,
        "show workspace status",
        "cheap readiness check",
    )
    .with_tool("workspace:status", Some(serde_json::json!({})))
    .with_preflight(kuzushi_core::StrategyPreflight::ready());
    proposal.id = "review-workspace-status".to_string();
    proposal.status = kuzushi_core::StrategyProposalStatus::Approved;
    kuzushi_core::append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app.reduce_strategy_command(&StrategyCommand::Fire);

    let [ShellEffect::FireNextApprovedStrategy(fire)] = effects.as_slice() else {
        panic!("strategy fire should return a fire-next effect");
    };
    assert_eq!(fire.target.as_deref(), Some(workspace.root()));
    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].status,
        kuzushi_core::StrategyProposalStatus::Approved
    );
    assert_eq!(app.running_tool_name(), None);

    EffectRuntime::execute(&mut app, effects);

    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].status,
        kuzushi_core::StrategyProposalStatus::Running
    );
    assert_eq!(app.running_tool_name(), Some("workspace:status"));
}

#[test]
fn strategy_correct_command_records_lineage_and_updates_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut proposal = kuzushi_core::StrategyProposal::new(
        kuzushi_core::StrategyPhase::Review,
        "run codeql:scan",
        "language coverage is present",
    )
    .with_source_run(Some("run-recommend".to_string()));
    proposal.id = "review-codeql-scan".to_string();
    kuzushi_core::append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(&mut app, parse_command(
        "strategy correct review-codeql-scan run codeql:scan with authz focus --workspace --reason tighten authz paths",
    ));

    assert_eq!(app.shell_view(), ShellView::StrategyQueue);
    let corrections = kuzushi_core::load_strategy_corrections(&workspace).unwrap();
    assert_eq!(corrections.len(), 1);
    assert_eq!(
        corrections[0].scope,
        kuzushi_core::StrategyCorrectionScope::Workspace
    );
    assert_eq!(corrections[0].reason, "tighten authz paths");
    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].corrected_strategy.as_deref(),
        Some("run codeql:scan with authz focus")
    );
    assert_eq!(queue[0].applied_corrections[0].author, "operator");
    assert!(
        app.log_lines().iter()
            .any(|line| line.prefix == "strategy"
                && line.body.contains(
                    "corrected review-codeql-scan: run codeql:scan -> run codeql:scan with authz focus (workspace)"
                ))
    );
}

#[test]
fn strategy_correct_reducer_returns_effect_without_writing_lineage() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut proposal = kuzushi_core::StrategyProposal::new(
        kuzushi_core::StrategyPhase::Review,
        "run codeql:scan",
        "language coverage is present",
    )
    .with_source_run(Some("run-recommend".to_string()));
    proposal.id = "review-codeql-scan".to_string();
    kuzushi_core::append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app.reduce_strategy_command(&StrategyCommand::Correct {
        id: "review-codeql-scan".to_string(),
        to_strategy: "run codeql:scan with authz focus".to_string(),
        reason: Some("tighten authz paths".to_string()),
        scope: StrategyCorrectionCommandScope::Workspace,
    });

    let [ShellEffect::RecordStrategyCorrection(record)] = effects.as_slice() else {
        panic!("strategy correct should return a correction record effect");
    };
    assert_eq!(record.target.as_deref(), Some(workspace.root()));
    assert_eq!(record.id, "review-codeql-scan");
    assert_eq!(record.to_strategy, "run codeql:scan with authz focus");
    assert_eq!(record.reason.as_deref(), Some("tighten authz paths"));
    assert_eq!(record.scope, StrategyCorrectionCommandScope::Workspace);
    assert_eq!(
        kuzushi_core::load_strategy_corrections(&workspace)
            .unwrap()
            .len(),
        0
    );
    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(queue[0].corrected_strategy, None);

    EffectRuntime::execute(&mut app, effects);

    let corrections = kuzushi_core::load_strategy_corrections(&workspace).unwrap();
    assert_eq!(corrections.len(), 1);
    let queue = kuzushi_core::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].corrected_strategy.as_deref(),
        Some("run codeql:scan with authz focus")
    );
}

#[test]
fn workspace_export_findings_to_temp_path() {
    let tmp = tempfile::tempdir().unwrap();
    let export_dir = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
            format: None,
            completeness: None,
            allow_empty: false,
        }),
    );

    assert_eq!(app.shell_view(), ShellView::Workspace);
    assert_eq!(app.domain().workspace_view().findings_count, Some(1));
    assert_eq!(
        app.domain().workspace_view().last_export.as_deref(),
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
fn workspace_export_honors_completeness_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let confirmed_id = store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/confirmed",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "confirmed finding",
            ),
        )
        .unwrap();
    store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/open",
                "src/app.ts",
                17,
                None,
                Severity::Medium,
                "open finding",
            ),
        )
        .unwrap();
    store
        .save_triage(
            confirmed_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.92,
                rationale: "operator confirmed".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    let output = tmp.path().join("open-findings.json");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
            format: Some("json".to_string()),
            completeness: Some("open".to_string()),
            allow_empty: false,
        }),
    );

    let exported: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(exported["metadata"]["completeness"], "open");
    assert_eq!(exported["metadata"]["includedCount"], 1);
    assert_eq!(exported["metadata"]["totalCount"], 2);
    assert_eq!(exported["findings"][0]["ruleId"], "fixture/open");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "export" && line.body.contains("completeness:open") }));
}

#[test]
fn refresh_findings_loads_review_decisions_without_mutating_triage() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding_id = store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/suppressed",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "suppressed finding",
            ),
        )
        .unwrap();
    store
        .append_user_review_decision(
            finding_id,
            &kuzushi_core::findings::ReviewDecision {
                verdict: kuzushi_core::findings::ReviewDecisionVerdict::Suppressed,
                author: kuzushi_core::findings::TriageAuthor::Human,
                confidence: 1.0,
                rationale: "suppressed by approved review policy".to_string(),
            },
        )
        .unwrap();
    drop(store);
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.refresh_findings(false);

    assert_eq!(app.findings().len(), 1);
    assert!(
        app.findings()[0].triage.is_none(),
        "review decisions must not be projected into scanner triage"
    );
    assert_eq!(app.review_decisions().len(), 1);
    assert_eq!(
        app.review_decisions()[0].decision.verdict,
        kuzushi_core::findings::ReviewDecisionVerdict::Suppressed
    );
}

#[test]
fn review_decision_command_saves_and_explains_filter_movement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding_id = store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/open",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "open finding",
            ),
        )
        .unwrap();
    drop(store);
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::FindingsFilter("completeness:open".to_string()),
    );

    run_command(
        &mut app,
        ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
            verdict: "suppressed".to_string(),
            reason: "reviewed under approved suppression policy".to_string(),
        }),
    );

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let latest = store
        .latest_review_decision(finding_id)
        .unwrap()
        .expect("saved review decision");
    assert_eq!(
        latest.decision.verdict,
        kuzushi_core::findings::ReviewDecisionVerdict::Suppressed
    );
    assert_eq!(latest.triage_verdict, None);
    assert_eq!(store.list_findings(10).unwrap()[0].triage, None);
    assert_eq!(
        app.active_findings_filter().as_deref(),
        Some("completeness:open")
    );
    assert!(app.findings().is_empty());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "review" && line.body.contains("decision saved; will carry forward")
    }));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "review"
            && line
                .body
                .contains("row moved because the active filter excludes it")
    }));
}

#[test]
fn review_decision_write_effect_returns_reload_followups_without_inline_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/open",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "open finding",
            ),
        )
        .unwrap();
    drop(store);
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::FindingsFilter("completeness:open".to_string()),
    );

    let effects = app
        .reduce_command_effects(&ShellCommand::ReviewDecision(
            ReviewDecisionCommand::Record {
                verdict: "suppressed".to_string(),
                reason: "reviewed under approved suppression policy".to_string(),
            },
        ))
        .expect("review decision should be effect-routed");
    let apply = review_decision_apply_owned(effects).expect("review decision effect");
    let followups = app.record_review_decision_effect(apply);

    assert_eq!(
        app.findings().len(),
        1,
        "write effect should not refresh the cached finding list inline"
    );
    assert!(matches!(
        &followups[..],
        [
            ShellEffect::RefreshFindings(FindingsRefresh {
                filter: Some(expression),
                ..
            }),
            ShellEffect::ReportFilteredFindingMovement(_)
        ] if expression == "completeness:open"
    ));

    EffectRuntime::execute(&mut app, followups);

    assert!(app.findings().is_empty());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "review"
            && line
                .body
                .contains("row moved because the active filter excludes it")
    }));
}

#[test]
fn review_decision_command_rejects_stale_workbench_watermark() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding_id = store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/open",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "open finding",
            ),
        )
        .unwrap();
    drop(store);
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, ShellCommand::Findings);
    let stable_fp = app.findings()[0]
        .identity_id
        .clone()
        .expect("stored finding should have a v3 stable identity");
    let read_watermark = kuzushi_core::storage_v3::ProjectionDb::open(workspace.findings_db_path())
        .unwrap()
        .meta()
        .unwrap()
        .applied_seq;
    app.router.workbench_mut().review_mut().replace_frame(
        vec![review_row_for_stale_test(&stable_fp)],
        read_watermark,
        1,
    );

    run_command(
        &mut app,
        ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
            verdict: "confirmed".to_string(),
            reason: "first read of this finding".to_string(),
        }),
    );
    run_command(
        &mut app,
        ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
            verdict: "suppressed".to_string(),
            reason: "stale second read".to_string(),
        }),
    );

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_review_decisions(finding_id).unwrap().len(), 1);
    assert!(matches!(
        app.router.workbench_mut().review_mut().mode,
        ReviewMode::Conflict { .. }
    ));
}

fn review_row_for_stale_test(stable_fp: &str) -> ReviewRow {
    ReviewRow {
        stable_fp: stable_fp.to_string(),
        observation_hash: "obs3_stale".to_string(),
        snapshot_hash: "snap3_stale".to_string(),
        blob_hash: None,
        byte_span: None,
        display_path: "src/app.ts".to_string(),
        display_line: 7,
        code_snippet: Vec::new(),
        trace_hops: Vec::new(),
        attestations: Vec::new(),
        verdict: "unreviewed".to_string(),
        confidence: 50,
        justification: None,
        provenance_refs: Vec::new(),
        projection_seq: 0,
    }
}

#[test]
fn review_decision_command_rejects_empty_reason_without_write() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding_id = store
        .insert_finding(
            "run-1",
            &Finding::new_tool(
                "fixture",
                "fixture/open",
                "src/app.ts",
                7,
                None,
                Severity::High,
                "open finding",
            ),
        )
        .unwrap();
    drop(store);
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::FindingsFilter("completeness:open".to_string()),
    );

    run_command(
        &mut app,
        ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
            verdict: "suppressed".to_string(),
            reason: "   ".to_string(),
        }),
    );

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store.latest_review_decision(finding_id).unwrap().is_none());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "review" && line.body.contains("review decision reason cannot be empty")
    }));
    assert!(!app.log_lines().iter().any(|line| {
        line.prefix == "review" && line.body.contains("decision saved; will carry forward")
    }));
}

#[test]
fn workspace_export_rejects_unsupported_formats_actionably() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: tmp.path().join("findings.xml"),
            format: None,
            completeness: None,
            allow_empty: false,
        }),
    );

    let error = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("unsupported workspace findings export extension"));
    assert!(error.contains("Next: workspace export findings <path>"));
    assert!(!tmp.path().join("findings.xml").exists());
}

#[test]
fn workspace_export_requires_allow_empty_for_empty_selection() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    FindingStore::open(workspace.findings_db_path()).unwrap();
    let output = workspace.root().join("exports/empty.json");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
            format: Some("json".to_string()),
            completeness: None,
            allow_empty: false,
        }),
    );

    let error = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("selected 0 findings"));
    assert!(error.contains("--allow-empty"));
    assert!(!workspace.root().join("exports").exists());

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
            format: Some("json".to_string()),
            completeness: None,
            allow_empty: true,
        }),
    );

    let exported: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(exported["count"], serde_json::json!(0));
    assert_eq!(exported["metadata"]["includedCount"], 0);
}

#[test]
fn workspace_export_accepts_explicit_markdown_bundle_format() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    seed_true_positive_finding(&workspace);
    let output = tmp.path().join("bundle");
    fs::create_dir(&output).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
            format: Some("markdown-bundle".to_string()),
            completeness: None,
            allow_empty: false,
        }),
    );

    assert_eq!(
        app.domain().workspace_view().last_export.as_deref(),
        Some(output.as_path())
    );
    assert!(output.join("README.md").is_file());
    assert!(output.join("manifest.json").is_file());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "export" && line.body.contains("(markdown-bundle)") }));
}

#[test]
fn workspace_export_extensionless_path_defaults_to_markdown_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    seed_true_positive_finding(&workspace);
    let output = tmp.path().join("report");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
            format: None,
            completeness: None,
            allow_empty: false,
        }),
    );

    assert!(output.join("README.md").is_file());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "export"
            && line.body.contains("(markdown-bundle)")
            && line.body.contains("README.md")
    }));
}

#[test]
fn workspace_scope_init_writes_editable_empty_scaffold() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(
        &mut app,
        ShellCommand::Workspace(WorkspaceCommand::ScopeInit),
    );

    let path = tmp.path().join(".kuzushi/scope.toml");
    let body = fs::read_to_string(&path).unwrap();
    assert!(body.contains("[in_scope]"));
    assert!(body.contains("hosts = []"));
    assert!(app
        .domain()
        .program_scope()
        .is_some_and(|scope| scope.is_empty()));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "scope" && line.body.contains("Edit in_scope/out_of_scope")
    }));
}

#[test]
fn workspace_scope_init_effect_defers_program_scope_reload_to_followup() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app.init_workspace_scope_effect(WorkspaceScopeInit {
        target: Some(workspace.root().to_path_buf()),
    });

    assert!(tmp.path().join(".kuzushi/scope.toml").exists());
    assert!(
        app.domain().program_scope().is_none(),
        "program scope reload ran inline"
    );
    assert!(program_scope_refresh_effect(&effects));

    EffectRuntime::execute(&mut app, effects);

    assert!(app
        .domain()
        .program_scope()
        .is_some_and(|scope| scope.is_empty()));
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
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("context:build".to_string()),
        "sampleLimit",
        serde_json::json!(1),
    );
    run_command(&mut app, ShellCommand::Use("context".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: None,
        },
    );
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
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("context:build".to_string()),
        "sampleLimit",
        serde_json::json!(1),
    );
    run_command(&mut app, ShellCommand::Use("context".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"sampleLimit":2}"#.to_string()),
        },
    );
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
    let temp = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.option_store_mut().set_value(
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
    let temp = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "disabled_tasks",
        serde_json::json!("semgrep,codeql"),
    );
    app.option_store_mut().set_value(
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

    run_command(&mut app, ShellCommand::Tasks);
    assert_eq!(app.shell_view(), ShellView::SastTasks);
    assert_eq!(app.focused_module(), Some("sast"));

    run_command(
        &mut app,
        ShellCommand::Task(SastTaskCommand::Block("semgrep".to_string())),
    );
    let prepared = app
        .registry()
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(app.option_store()))
        .unwrap();
    assert_eq!(prepared["disabledTasks"], serde_json::json!(["semgrep"]));

    assert_eq!(prepared["disabledTasks"], serde_json::json!(["semgrep"]));
    assert_eq!(prepared["taskMode"], serde_json::json!("auto"));
    assert_eq!(prepared.get("disabled_tasks"), None);
}

#[test]
fn task_mode_manual_seeds_and_allows_tasks_for_sast_scan() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(
        &mut app,
        ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Manual)),
    );
    run_command(
        &mut app,
        ShellCommand::Task(SastTaskCommand::Allow("codeql".to_string())),
    );

    let prepared = app
        .registry()
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(app.option_store()))
        .unwrap();
    assert_eq!(prepared["taskMode"], serde_json::json!("manual"));
    assert!(prepared["tasks"]
        .as_array()
        .is_some_and(|tasks| tasks.iter().any(|task| task == "codeql")));
}

#[test]
fn unknown_task_id_lists_valid_ids_and_does_not_mutate_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(
        &mut app,
        ShellCommand::Task(SastTaskCommand::Block("semgrep".to_string())),
    );
    let before = app.option_store().clone();

    run_command(
        &mut app,
        ShellCommand::Task(SastTaskCommand::Allow("bogus-task".to_string())),
    );

    assert_eq!(app.option_store(), &before);
    let error = app
        .log_lines()
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

    run_command(&mut app, ShellCommand::Findings);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "findings" && line.body.contains("Next: scan") }));

    let mut no_workspace_app = ShellApp::new(V2Config::default(), None);
    run_command(
        &mut no_workspace_app,
        ShellCommand::Workspace(WorkspaceCommand::Status),
    );
    assert!(no_workspace_app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "workspace" && line.body.contains("Next: scan <target>") }));

    run_command(&mut app, ShellCommand::Use("sat".to_string()));
    let unknown_module = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(unknown_module.contains("unknown module"));
    assert!(unknown_module.contains("Closest: sast"));
    assert!(unknown_module.contains("Next: modules or use <module-id>"));

    let error_count = app
        .log_lines()
        .iter()
        .filter(|line| line.prefix == "error")
        .count();
    run_command(&mut app, ShellCommand::Use("recon".to_string()));
    assert_eq!(app.focused_module(), Some("recon"));
    assert_eq!(
        app.log_lines()
            .iter()
            .filter(|line| line.prefix == "error")
            .count(),
        error_count
    );

    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("missing:tool".to_string()),
            input: None,
        },
    );
    let unknown_tool = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(unknown_tool.contains("unknown tool"));
    assert!(unknown_tool.contains("Next:"));
    assert!(unknown_tool.contains("tools"));

    let before = app.option_store().clone();
    run_command(
        &mut app,
        ShellCommand::Task(SastTaskCommand::Allow("not-a-task".to_string())),
    );
    assert_eq!(app.option_store(), &before);
    let unknown_task = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(unknown_task.contains("Valid task IDs"));
    assert!(unknown_task.contains("Next: /tasks"));

    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.apply_scan_event(ScanEvent::Failed {
        error: "semgrep: could not find scanner binary \"semgrep\"".to_string(),
    });
    let missing_scanner = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(missing_scanner.contains("could not find scanner binary"));
    assert!(missing_scanner.contains("Next:"));
    assert!(missing_scanner.contains("task block semgrep"));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error"
            && line.body.contains("stage=scan task=sast:scan")
            && line.body.contains("could not find scanner binary")
    }));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "result" && line.body == "fail (scan failed) exit_hint=1"));

    app.apply_scan_event(ScanEvent::Failed {
        error: "internal shell-state error: selected finding disappeared".to_string(),
    });
    let internal = app
        .log_lines()
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
    run_command(&mut app, ShellCommand::Use("threat-model".to_string()));

    run_command(&mut app, ShellCommand::Attach("notes.md".to_string()));

    assert_eq!(app.shell_view(), ShellView::KnowledgeBase);
    assert_eq!(app.domain().kb_view().module_id, "threat-model");
    assert!(workspace
        .root()
        .join(".kuzushi/v3/attachments.json")
        .exists());
    let record = app
        .domain()
        .kb_view()
        .attachments
        .iter()
        .find(|record| record.module_id == "threat-model")
        .cloned()
        .unwrap();
    assert_eq!(record.source, "notes.md");
    let first_hash = record.content_hash.clone();

    fs::write(tmp.path().join("notes.md"), "second\n").unwrap();
    run_command(&mut app, ShellCommand::Reparse(record.id.clone()));
    let reparsed = app
        .domain()
        .kb_view()
        .attachments
        .iter()
        .find(|candidate| candidate.id == record.id)
        .unwrap();
    assert_ne!(first_hash, reparsed.content_hash);

    run_command(&mut app, ShellCommand::Detach(record.id));
    assert!(app.domain().kb_view().attachments.is_empty());
}

#[test]
fn kb_records_url_metadata_without_fetching() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::KnowledgeBase(Some("x-ray".to_string())),
    );
    run_command(
        &mut app,
        ShellCommand::Attach("https://example.test/x-ray-notes".to_string()),
    );

    let record = app
        .domain()
        .kb_view()
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

    run_command(
        &mut app,
        ShellCommand::KnowledgeBase(Some("unknown".to_string())),
    );
    let unknown_module = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(unknown_module.contains("Supported KB modules"));

    run_command(
        &mut app,
        ShellCommand::Attach(outside.path().display().to_string()),
    );
    let unsafe_path = app
        .log_lines()
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
    app.replace_option_store_for_test(ToolOptionStore::new());

    run_command(&mut app, ShellCommand::Use("context".to_string()));
    run_command(
        &mut app,
        ShellCommand::Options {
            tool: None,
            filter: OptionsFilter::Standard,
        },
    );
    run_command(
        &mut app,
        ShellCommand::SetOption {
            global: false,
            name: "sampleLimit".to_string(),
            value: "1".to_string(),
        },
    );
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: None,
        },
    );
    drain_tool(&mut app);

    let snapshot =
        fs::read_to_string(kuzushi_core::context_snapshot_path(workspace.root())).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(snapshot["filesSample"].as_array().unwrap().len(), 1);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "set" && line.body.contains("context:build.sampleLimit")));
}

#[test]
fn setg_and_unsetg_apply_tool_scoped_persistent_options() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(
        &mut app,
        ShellCommand::Options {
            tool: Some("sast:scan".to_string()),
            filter: OptionsFilter::Standard,
        },
    );
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::All,
        "triage",
        serde_json::json!(false),
    );
    run_command(
        &mut app,
        ShellCommand::SetOption {
            global: true,
            name: "triage".to_string(),
            value: "true".to_string(),
        },
    );

    let prepared = app
        .registry()
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(app.option_store()))
        .unwrap();
    assert_eq!(prepared["triage"], serde_json::json!(true));
    assert_eq!(
        app.option_store()
            .values_for(
                OptionScope::Global,
                &OptionTarget::Tool("sast:scan".to_string())
            )
            .and_then(|values| values.get("triage")),
        Some(&serde_json::json!(true))
    );
    assert!(app
        .option_store()
        .values_for(OptionScope::Global, &OptionTarget::All)
        .and_then(|values| values.get("triage"))
        .is_none());

    run_command(
        &mut app,
        ShellCommand::UnsetOption {
            global: true,
            name: "triage".to_string(),
        },
    );
    let prepared = app
        .registry()
        .prepare_tool_input("sast:scan", serde_json::json!({}), Some(app.option_store()))
        .unwrap();
    assert_eq!(prepared["triage"], serde_json::json!(false));
    assert!(app
        .option_store()
        .values_for(
            OptionScope::Global,
            &OptionTarget::Tool("sast:scan".to_string())
        )
        .and_then(|values| values.get("triage"))
        .is_none());
}

#[test]
fn auto_open_prefs_respect_shell_options() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(app.ui().auto_open_activity());
    assert!(app.ui().auto_open_viz());

    run_command(
        &mut app,
        ShellCommand::SetOption {
            global: false,
            name: "ui.auto_open_activity".to_string(),
            value: "false".to_string(),
        },
    );
    run_command(
        &mut app,
        ShellCommand::SetOption {
            global: false,
            name: "ui.auto_open_viz".to_string(),
            value: "off".to_string(),
        },
    );

    assert!(!app.ui().auto_open_activity());
    assert!(!app.ui().auto_open_viz());
    assert_eq!(
        app.option_store()
            .values_for(OptionScope::Session, &OptionTarget::All)
            .unwrap()
            .get("ui.auto_open_activity"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn unknown_option_reports_closest_names_and_next_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(
        &mut app,
        ShellCommand::Options {
            tool: Some("context:build".to_string()),
            filter: OptionsFilter::Standard,
        },
    );
    run_command(
        &mut app,
        ShellCommand::SetOption {
            global: false,
            name: "sampleLmit".to_string(),
            value: "1".to_string(),
        },
    );

    let error = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(error.contains("Closest: sampleLimit"));
    assert!(error.contains("Next: show options context:build"));
}

#[test]
fn auth_status_reducer_returns_show_effect_without_reading_env() {
    let mut config = V2Config::default();
    config.runtime.api_key_env = "KUZUSHI_BG011_TEST_SECRET".to_string();
    let mut app = ShellApp::new(config, None);

    let result = update(&mut app, Msg::Cmd(ShellCommand::Auth));

    assert!(result.changed);
    assert_eq!(app.shell_view(), ShellView::Auth);
    let show = auth_status_show_effect(&result.effects).expect("auth status effect");
    assert_eq!(show.api_key_env, "KUZUSHI_BG011_TEST_SECRET");
    assert!(
        app.log_lines().iter().all(|line| line.prefix != "auth"),
        "status logging belongs to the effect runtime"
    );
}

#[test]
fn auth_login_reducer_returns_login_effect_without_spawning_process() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::AuthLogin(Some("openai headless".to_string()))),
    );

    assert!(result.changed);
    assert_eq!(app.shell_view(), ShellView::Auth);
    let login = app.router.auth().login().expect("auth login view");
    assert_eq!(login.provider, "openai");
    assert_eq!(login.method, "headless");
    assert_eq!(login.status, "starting");
    let effect = auth_login_effect(&result.effects).expect("auth login effect");
    assert_eq!(effect.provider, "openai-codex");
    assert_eq!(effect.method, "headless");
    assert!(!effect.continue_after_success);
    assert!(!app.ui().force_full_redraw());
}

#[test]
fn auth_picker_oauth_returns_login_effect_with_continuation() {
    let _env_lock = env_test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let _home = EnvVarGuard::set("HOME", tmp.path().to_string_lossy().as_ref());
    let _key = EnvVarGuard::unset("OPENAI_API_KEY");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.auth_picker_mut().open("openai".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);
    app.router.auth_picker_mut().set_cursor(1);

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    let effect = auth_login_effect(&result.effects).expect("auth login effect");
    assert_eq!(effect.provider, "openai-codex");
    assert_eq!(effect.method, "browser");
    assert!(effect.continue_after_success);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "onboarding" && line.body.contains("dispatching OAuth login for openai")
    }));
    assert!(!app.ui().force_full_redraw());
}

#[test]
fn auth_provider_backend_model_and_cost_commands_are_explicit_and_secret_safe() {
    let mut config = V2Config::default();
    config.runtime.api_key_env = "KUZUSHI_BG011_TEST_SECRET".to_string();
    config.model = Some("openai:gpt-4.1".to_string());
    let mut app = ShellApp::new(config, None);

    run_command(&mut app, ShellCommand::Auth);
    let auth = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "auth")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(auth.contains("KUZUSHI_BG011_TEST_SECRET"));
    assert!(auth.contains("secret values hidden"));
    assert!(auth.contains("openai oauth"));
    assert!(!auth.contains("sk-"));

    run_command(
        &mut app,
        ShellCommand::AuthLogin(Some("not-a-provider".to_string())),
    );
    assert_eq!(app.shell_view(), ShellView::Auth);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("unsupported auth login provider")
    }));

    run_command(&mut app, ShellCommand::Provider(None));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "provider" && line.body.contains("openai") }));

    run_command(
        &mut app,
        ShellCommand::Backend(Some("not-a-backend".to_string())),
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "error" && line.body.contains("Supported: LangGraph") }));

    run_command(&mut app, ShellCommand::Model(Some("gpt-4.1".to_string())));
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-4.1"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "error" && line.body.contains("provider:model") }));

    run_command(
        &mut app,
        ShellCommand::Model(Some("openai:gpt-4.1-mini".to_string())),
    );
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-4.1-mini"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "model" && line.body.contains("no fallback model") }));

    run_command(&mut app, ShellCommand::Model(Some("openai:".to_string())));
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-4.1-mini"));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("both provider and model id")
    }));

    run_command(
        &mut app,
        ShellCommand::Model(Some("1 xtrahigh".to_string())),
    );
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    assert_eq!(app.session_thinking_level(), Some("xhigh"));

    run_command(&mut app, ShellCommand::Use("randori".to_string()));
    run_command(&mut app, ShellCommand::Model(Some("5 high".to_string())));
    let stored = app.option_store().effective_stored_values("randori:pasta");
    assert_eq!(
        stored.get("model").and_then(serde_json::Value::as_str),
        Some("anthropic:claude-sonnet-4-6")
    );
    assert_eq!(
        stored.get("effort").and_then(serde_json::Value::as_str),
        Some("high")
    );

    app.session_mut()
        .set_last_tool_cost_usd_for_test(Some(0.0123));
    app.session_mut().set_session_cost_usd_for_test(0.0456);
    run_command(&mut app, ShellCommand::Cost);
    assert!(app
        .log_lines()
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
fn doctor_verb_opens_shell_health_not_agent_chat() {
    assert_eq!(parse_command("doctor"), ShellCommand::Health);
    assert_eq!(parse_command("health"), ShellCommand::Health);

    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Health);

    assert_eq!(app.shell_view(), ShellView::Health);
    assert!(app.log_lines().iter().any(|line| line.prefix == "health"));

    let message = unknown_command_message("pr-comment");
    assert!(message.contains("CLI subcommand"));
    assert!(message.contains("kuzushi pr-comment"));
    assert!(!message.contains("Free-form chat"));

    // Plain unknown verb still uses the agent-path fallback.
    let message = unknown_command_message("zzwombat");
    assert!(message.contains("Free-form chat"));
}

#[test]
fn unknown_command_suggests_nearby_shell_verb() {
    let message = unknown_command_message("scn");

    assert!(message.contains("Did you mean `scan`?"), "{message}");
    assert!(message.contains("Next: `scan` or /help"), "{message}");
    assert!(!message.contains("Free-form chat"), "{message}");
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
    assert!(app.target().is_none());
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
    assert!(app.target().is_none(), "self.target must not be mutated");
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
    let log_count_before = app.log_len();
    assert!(log_count_before > 1);

    // Mid-command Ctrl+L: log clears, input survives, no stray 'l'.
    app.set_input("scan ./repo");
    let cursor_before = app.cursor();
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input(), "scan ./repo");
    assert_eq!(app.cursor(), cursor_before);
    assert!(app.log_len() < log_count_before);
    assert!(app
        .log_lines()
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
    let log_count = app.log_len();
    let history_count = app.command_history().len();

    submit_shell_line(&mut app, "");
    submit_shell_line(&mut app, "    ");
    submit_shell_line(&mut app, "\t \t");

    assert_eq!(app.log_len(), log_count);
    assert_eq!(app.command_history().len(), history_count);
}

#[test]
fn options_dot_resolves_to_focused_module_primary_tool() {
    // The module-view footer advertises `help options . · prompts ·
    // tune · back`, but `options .` errored with `unknown tool "."`
    // because "." was looked up directly. Now it resolves to the
    // focused module's primary tool, mirroring `run .`.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("codeql".to_string()));
    let resolved = app
        .resolve_options_tool(Some(".".to_string()))
        .expect("`options .` with codeql focused should resolve");
    assert_eq!(resolved, "codeql:scan");

    // Without a focused module the helper produces a useful error so
    // the user knows to `use <module>` first.
    app.clear_focused_module();
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

    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    let first = app.input().to_string();
    assert!(
        first.starts_with("use s"),
        "expected use s* candidate, got {first:?}"
    );

    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    let second = app.input().to_string();
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
        press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
        seen.push(app.input().to_string());
        if app.input() == first && seen.len() > 2 {
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
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );
    assert!(app.completion_cycle().is_none());
    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert!(
        app.input().starts_with("use co"),
        "Tab after 'use co' should pick a co* candidate, got {:?}",
        app.input()
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
    let prefix = app.input().to_string();
    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert!(
        app.completion_cycle().is_some(),
        "Tab must open a completion cycle when candidates are available"
    );
    assert_ne!(app.input(), prefix, "Tab applied the first candidate");

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert!(app.completion_cycle().is_none(), "Esc closes the cycle");
    assert_eq!(
        app.input(),
        prefix,
        "Esc must restore the operator's typed prefix"
    );
}

#[test]
fn esc_stashes_input_and_ctrl_underscore_restores_it() {
    // Esc clears the draft without losing it, but empty-prompt Esc remains
    // navigation. Restore is an explicit Ctrl+_ / Ctrl+/ action so hidden
    // draft state never changes what Esc means.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("scan ./very/specific/path with --since main --include-worktree");
    let original = app.input().to_string();
    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.input().is_empty(), "first Esc clears the input");

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('_'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input(), original, "Ctrl+_ restores the draft");
    assert_eq!(app.cursor(), original.chars().count());

    // Restoring consumed the stash; another Esc cycle starts fresh.
    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.input().is_empty(), "Esc clears again");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('/'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input(), original, "Ctrl+/ also restores the new stash");
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
    app.set_focused_module(Some("sast".to_string()));
    assert!(app.config().model.is_none());

    run_command(&mut app, ShellCommand::Model(Some("5".to_string())));
    assert_eq!(
        app.config().model.as_deref(),
        Some("anthropic:claude-sonnet-4-6"),
        "first model selection with focused module must set global so /ask works"
    );

    // After a global is set, the next `model <n>` scopes per-module so
    // operators can override per-tool without losing the global default.
    run_command(&mut app, ShellCommand::Model(Some("6".to_string())));
    assert_eq!(
        app.config().model.as_deref(),
        Some("anthropic:claude-sonnet-4-6"),
        "second model selection must NOT clobber the global"
    );
    let module_values = app
        .option_store()
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
    app.set_shell_view(ShellView::Config);
    // The Config view hides the non-primary OpenAI row (which varies with auth
    // state), so navigation steps the *visible* set — derive expectations from
    // it rather than hardcoding an index, and assert the Enter target is exactly
    // the highlighted (visible) row, not a hidden one.
    let visible = super::settings::visible_model_choice_indexes(app.config().model.as_deref());
    let choices = super::settings::model_choices();
    app.router
        .model_catalog_mut()
        .set_selected_index(visible[0]);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.model_catalog().selected_index(),
        visible[1 % visible.len()]
    );

    press_key(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.router.model_catalog().selected_index(), visible[0]);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    let expected = choices[visible[0]];
    assert_eq!(app.config().model.as_deref(), Some(expected.id));
    assert_eq!(app.session_thinking_level(), Some(expected.thinking_level));
    assert!(
        app.log_lines()
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
    app.router.auth_picker_mut().open("openai".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);
    app.set_input("leftover");

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.auth_picker().cursor(),
        1,
        "j must move the picker cursor"
    );
    assert_eq!(
        app.input(),
        "leftover",
        "navigation must not edit the prompt"
    );
}

#[test]
fn auth_picker_swallows_typed_characters() {
    // Printable keys are consumed by the modal as a masked API-key draft; they
    // never leak into the prompt or command history.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.auth_picker_mut().open("anthropic".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);
    app.clear_input();

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()),
    );
    assert!(
        app.input().is_empty(),
        "picker must swallow typed characters"
    );
    assert_eq!(app.router.auth_picker().key_draft(), "x");
}

#[test]
fn auth_picker_swallows_shifted_typed_characters() {
    // Some terminals deliver uppercase printables as Char + SHIFT. Those are
    // still plain picker input, not shell chords.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.auth_picker_mut().open("openai".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('H'), KeyModifiers::SHIFT),
    );
    assert!(
        app.input().is_empty(),
        "picker must swallow shifted printable characters"
    );
    assert_eq!(app.router.auth_picker().key_draft(), "H");
}

#[test]
fn auth_picker_accepts_pasted_api_key_without_relaunch_or_logging_secret() {
    let _env_lock = env_test_lock();
    let _guard = EnvVarGuard::unset("OPENAI_API_KEY");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.auth_picker_mut().open("openai".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);

    paste_text(&mut app, "sk-test-secret");
    assert_eq!(app.router.auth_picker().key_draft(), "sk-test-secret");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(
        std::env::var("OPENAI_API_KEY").as_deref(),
        Ok("sk-test-secret")
    );
    assert!(app.router.auth_picker().key_draft().is_empty());
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "onboarding"
            && line
                .body
                .contains("OPENAI_API_KEY accepted for this session")
    }));
    assert!(
        app.log_lines()
            .iter()
            .all(|line| !line.body.contains("sk-test-secret")),
        "secret must never be logged"
    );
    assert!(
        app.command_history()
            .iter()
            .all(|entry| !entry.contains("sk-test-secret")),
        "secret must never enter command history"
    );
}

#[test]
fn auth_picker_enter_returns_session_env_effect_without_setting_secret() {
    let _env_lock = env_test_lock();
    let _guard = EnvVarGuard::unset("OPENAI_API_KEY");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.auth_picker_mut().open("openai".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);

    paste_text(&mut app, "sk-test-secret");
    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    let persist = global_model_persist_effect(&result.effects).expect("model persist effect");
    assert_eq!(persist.model, "openai:gpt-5.5");
    assert_eq!(persist.thinking_level.as_deref(), Some("xhigh"));
    let env = result
        .effects
        .iter()
        .find_map(|effect| match effect {
            ShellEffect::SetSessionEnv(env) => Some(env),
            _ => None,
        })
        .expect("session env effect");
    assert_eq!(env.key, "OPENAI_API_KEY");
    assert_eq!(env.value, "sk-test-secret");
    assert!(std::env::var_os("OPENAI_API_KEY").is_none());
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    assert!(app.router.auth_picker().key_draft().is_empty());

    EffectRuntime::execute(&mut app, result.effects);

    assert_eq!(
        std::env::var("OPENAI_API_KEY").as_deref(),
        Ok("sk-test-secret")
    );
}

#[test]
fn model_picker_shows_openai_oauth_before_login() {
    let _env_lock = env_test_lock();
    let _guard = EnvVarGuard::unset("OPENAI_API_KEY");
    let choices = super::settings::visible_model_choices(None);
    assert!(
        choices
            .iter()
            .any(|choice| choice.id == "openai-codex:gpt-5.4"),
        "OpenAI OAuth must be visible before credentials exist"
    );
}

#[test]
fn picker_footer_omits_tab_complete_hint() {
    // Tab does nothing in a modal picker, so the footer must not claim it
    // completes — that contradicted the picker's own hint row.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.auth_picker_mut().open("openai".to_string());
    app.set_shell_view(ShellView::AuthMethodPicker);
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(
        !bindings.iter().any(|binding| binding.key == "Tab"),
        "picker footer must not advertise Tab complete"
    );
    assert!(
        bindings
            .iter()
            .any(|binding| binding.key == "demo" && binding.label == "offline"),
        "picker footer should advertise the offline demo escape hatch"
    );
}

#[test]
fn picker_colon_focuses_prompt_and_esc_returns_to_picker() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::PlanningPicker);
    app.engagement.set_phase(WorkflowPhase::Map);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert!(
        app.input().is_empty(),
        "list-focused picker swallows letters"
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char(':'), KeyModifiers::empty()),
    );
    assert_eq!(
        app.engagement.planning_picker().focus(),
        PickerFocus::Prompt
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.input(), "j", "prompt-focused picker accepts typing");

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.engagement.planning_picker().focus(), PickerFocus::List);
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(
        app.input().is_empty(),
        "leaving prompt focus clears hidden draft"
    );
}

#[test]
fn picker_prompt_focus_restores_tab_completion_hint() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::PlanningPicker);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char(':'), KeyModifiers::empty()),
    );

    let bindings = crate::ui_view_models::footer_keybindings(&app);

    assert_eq!(bindings[0].key, "Tab");
    assert_eq!(bindings[0].label, "complete");
    assert!(bindings
        .iter()
        .any(|binding| binding.key == "Esc" && binding.label == "return to picker"));
    assert!(!bindings
        .iter()
        .any(|binding| binding.key == "j/k" && binding.label == "move"));
}

#[test]
fn ask_requires_explicit_model_and_unknown_prose_stays_deterministic() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);

    run_command(&mut app, parse_command("summarize this repo"));

    assert_eq!(app.shell_view(), ShellView::Home);
    assert!(app.agent_chat().is_none());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("Free-form chat is explicit only")
    }));

    run_command(&mut app, parse_command("/ask What should I run first?"));

    assert_eq!(app.shell_view(), ShellView::AgentChat);
    let agent = app.agent_chat().unwrap();
    assert_eq!(agent.question, "What should I run first?");
    assert!(!agent.running);
    assert!(agent
        .error
        .as_deref()
        .is_some_and(|error| error.contains("explicit model")));
}

#[test]
fn exit_and_unknown_command_feedback_is_actionable() {
    for command in ["/exit", "exit"] {
        let mut app = ShellApp::new(V2Config::default(), None);

        submit_shell_line(&mut app, command);

        assert!(app.should_quit(), "{command} should request shutdown");
        assert!(app.agent_chat().is_none());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.prefix == ">" && line.body == command));
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "system" && line.body.contains("exit requested; closing shell")
        }));
    }

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);
    submit_shell_line(&mut app, "/exitj");

    assert!(!app.should_quit());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("unknown command \"/exitj\"")
    }));

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);
    submit_shell_line(&mut app, "/definitely-not-real");
    let slash_error = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(slash_error.contains("Next: /help"));
    assert!(app.agent_chat().is_none());
    assert!(!app.should_quit());

    submit_shell_line(&mut app, "ask");
    let missing_ask_error = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "error")
        .map(|line| line.body.as_str())
        .unwrap_or_default();
    assert!(missing_ask_error.contains("Next: /ask <question>"));
    assert!(app.agent_chat().is_none());
    assert_eq!(app.shell_view(), ShellView::Home);
}

#[test]
fn plain_scripted_unknown_command_prints_command_and_new_error_log() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);

    let output = render_plain_scripted_session(&mut app, &["/nope"], 80);

    assert!(output.contains("COMMAND RESULT"));
    assert!(output.contains("command: /nope"));
    assert!(output.contains("> /nope"));
    assert!(output.contains("error: unknown command \"/nope\". Next: /help"));
    assert_eq!(app.shell_view(), ShellView::Home);
    assert_plain_output_strict_80(&output);
}

#[test]
fn plain_scripted_quit_prints_exit_acknowledgement() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let output = render_plain_scripted_session(&mut app, &["/quit"], 80);

    assert!(app.should_quit());
    assert!(output.contains("command: /quit"));
    assert!(output.contains("> /quit"));
    assert!(output.contains("system: exit requested; closing shell"));
    assert_plain_output_strict_80(&output);
}

#[test]
fn plain_scripted_help_then_quit_prints_one_result_block_per_command() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let output = render_plain_scripted_session(&mut app, &["/help", "/quit"], 80);

    assert!(app.should_quit());
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
    app.set_shell_view(ShellView::Workbench);
    let before = app.shell_view().clone();

    let output = render_plain_scripted_session(&mut app, &["/workbench"], 80);

    assert_eq!(app.shell_view(), before);
    assert!(output.contains("COMMAND RESULT"));
    assert!(output.contains("command: /workbench"));
    assert!(output.contains("> /workbench"));
    assert!(output.contains("workbench"));
    assert!(output.contains("FINDINGS"));
    assert_plain_output_strict_80(&output);
}

#[test]
fn session_history_clear_load_resume_pause_and_story_are_explicit() {
    let mut app = ShellApp::new(V2Config::default(), None);

    submit_shell_line(&mut app, "modules");
    submit_shell_line(&mut app, "/history");

    assert_eq!(app.shell_view(), ShellView::History);
    assert_eq!(
        app.command_history(),
        vec!["modules".to_string(), "/history".to_string()]
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "history" && line.body.contains("2 command")));

    submit_shell_line(&mut app, "/clear");

    assert_eq!(
        app.command_history(),
        vec![
            "modules".to_string(),
            "/history".to_string(),
            "/clear".to_string()
        ]
    );
    assert_eq!(app.log_len(), 1);
    assert!(app.log_lines()[0].body.contains("Conversation cleared"));

    run_command(&mut app, parse_command("/load builtin:sast"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "load" && line.body.contains("already available") }));

    run_command(&mut app, parse_command("/load file:///tmp/module.js"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "error" && line.body.contains("is not trusted") }));

    run_command(&mut app, parse_command("/pause"));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "pause" && line.body.contains("no live pause/resume control")
    }));

    run_command(&mut app, parse_command("/resume run-123"));
    assert_eq!(app.shell_view(), ShellView::Replay);
    assert_eq!(app.router.replay().run_id(), "run-123");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "resume" && line.body.contains("replay run-123") }));

    run_command(&mut app, parse_command("/story"));
    assert_eq!(app.shell_view(), ShellView::Story);
}

#[test]
fn replay_latest_resolves_latest_run_pointer() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    fs::create_dir_all(tmp.path().join(".kuzushi/v3")).unwrap();
    fs::write(tmp.path().join(".kuzushi/v3/latest"), "run-latest\n").unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(&mut app, parse_command("replay latest"));

    assert_eq!(app.shell_view(), ShellView::Replay);
    assert_eq!(app.router.replay().run_id(), "run-latest");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "replay" && line.body == "run-latest"));
}

#[test]
fn trace_latest_resolves_latest_run_pointer() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    fs::create_dir_all(tmp.path().join(".kuzushi/v3")).unwrap();
    fs::write(tmp.path().join(".kuzushi/v3/latest"), "run-latest\n").unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(&mut app, parse_command("trace latest"));

    assert_eq!(app.shell_view(), ShellView::Trace);
    assert_eq!(app.router.trace().run_id(), "run-latest");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "trace" && line.body == "run-latest"));
}

#[test]
fn replay_latest_without_target_is_actionable() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, parse_command("replay latest"));

    assert_ne!(app.shell_view(), ShellView::Replay);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("replay latest needs a target")
    }));
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
        api_key_env: "OPENAI_API_KEY".to_string(),
        base_url: None,
        thinking_level: None,
        langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(tmp.path().to_path_buf()));

    run_command(&mut app, parse_command("?What should I run first?"));

    assert_eq!(app.shell_view(), ShellView::AgentChat);
    let running_agent = app.agent_chat().unwrap();
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

    let agent = app.agent_chat().unwrap();
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
        Some("Run context build, then next"),
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
        .log_lines()
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
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("recon:nmap".to_string()),
            input: Some(format!(
                r#"{{"target":"192.0.2.10","ports":"80,443","binary":"{}"}}"#,
                binary.display()
            )),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| {
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
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("recon:http-fingerprint".to_string()),
            input: Some(format!(
                r#"{{"target":"https://www.example.com","binary":"{}"}}"#,
                binary.display()
            )),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| {
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
    run_command(&mut app, ShellCommand::Use("secret-scan".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: None,
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
    run_command(&mut app, ShellCommand::Use("semgrep".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"binary":"{}","config":"p/security-audit"}}"#,
                binary.display()
            )),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
    run_command(&mut app, ShellCommand::Use("codeql".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"binary":"{}","language":"javascript"}}"#,
                binary.display()
            )),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
    run_command(&mut app, ShellCommand::Use("iac-scan".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"kind":"terraform"}"#.to_string()),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
    run_command(&mut app, ShellCommand::Use("cargo-audit".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: None,
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| {
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
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(&mut app, ShellCommand::Use("sast".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(
                r#"{"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#.to_string(),
            ),
        },
    );
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(
        &mut app,
        parse_command(r#"run . {"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#),
    );
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.focused_module().is_none());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "tool" && line.body.contains("running sast:scan")));
    assert!(app
        .log_lines()
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(&mut app, ShellCommand::Use("agentic-sast".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"maxFindings":5}"#.to_string()),
        },
    );
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("variant".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"fingerprint":"{fingerprint}","maxFindings":5}}"#
            )),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("ndiff".to_string()));
    run_command(&mut app, ShellCommand::RunTool {
            tool: Some("hunt-variants".to_string()),
            input: Some(
                r#"{"advisoryId":"CVE-2024-1234","pattern":{"fixShape":"adds a bounds check before memcpy","vulnerableShape":"memcpy uses attacker-controlled length without a bounds check","cwe":["CWE-787"],"languages":["c"],"keywords":["memcpy","len"],"detectionQuery":"rg 'memcpy\\('","description":"Search copies guarded by no length cap.","confidence":"HIGH"}}"#
                    .to_string(),
            ),
        });
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| {
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("taint-iris:hunt".to_string()),
            input: Some(r#"{"maxFindings":5,"mcps":false}"#.to_string()),
        },
    );
    drain_chain_with_auto_reuse(&mut app);

    // The compatibility path now runs the taint-iris-next report shape. It
    // persists findings, but emits no structured `data.flows[]`; the AttackPath
    // page correctly stays closed rather than showing an empty visualization.
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.domain().taint_flow().is_none());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "result"
            && line.body.contains("Taint IRIS Next")
            && line.body.contains("findings: 1")
    }));

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(&mut app, ShellCommand::Use("taint-iris-next".to_string()));
    run_command(&mut app, ShellCommand::RunTool {
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
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        app.log_lines().iter().any(|line| {
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("carlini-threat-hunt:run".to_string()),
            input: Some(r#"{"maxActors":1,"runsPerActor":1}"#.to_string()),
        },
    );
    drain_chain_with_auto_reuse(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| {
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("systems-hunt:systems-hunt".to_string()),
            input: Some(r#"{"maxFindings":5}"#.to_string()),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
        .record_run_started("run-1", workspace.root(), "completed")
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
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("findings:list".to_string()),
            input: Some(r#"{"severity":["high"],"verdict":["tp"],"name":"sql"}"#.to_string()),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "result"
            && line.body.contains("SQL injection in search")
            && line.body.contains("1 matching")
    }));
}

#[test]
fn findings_filter_command_loads_filtered_rows_into_workbench() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("scan-a", workspace.root(), "completed")
        .unwrap();
    store
        .record_run_started("scan-b", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding(
            "scan-a",
            &Finding::new_semgrep(
                "demo.sql",
                "src/db.ts",
                12,
                Some(12),
                Severity::High,
                "SQL injection in search",
            ),
        )
        .unwrap();
    store
        .insert_finding(
            "scan-b",
            &Finding::new_semgrep(
                "demo.token",
                "src/token.ts",
                2,
                Some(2),
                Severity::Low,
                "Hardcoded token",
            ),
        )
        .unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let expression = "state:new rank:high run:scan-a sql".to_string();
    let initial_findings_count = app.findings().len();
    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::FindingsFilter(expression.clone())),
    );

    assert!(result.changed);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert_eq!(
        app.findings().len(),
        initial_findings_count,
        "filtered findings should load through the effect runtime"
    );
    assert_eq!(
        filtered_findings_refresh_effect(&result.effects),
        Some(expression.as_str())
    );

    EffectRuntime::execute(&mut app, result.effects);

    assert_eq!(app.findings().len(), 1);
    assert_eq!(app.findings()[0].rule_id, "demo.sql");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "findings" && line.body.contains("loaded 1 of 1 matching") }));
}

#[test]
fn findings_filter_command_matches_run_revision_metadata() {
    let (_tmp, workspace) = workspace_with_revision_findings();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(
        &mut app,
        ShellCommand::FindingsFilter("sha:abcdef1 branch:main dirty:true".to_string()),
    );

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert_eq!(app.findings().len(), 1);
    assert_eq!(app.findings()[0].rule_id, "demo.sql");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "findings" && line.body.contains("loaded 1 of 1 matching") }));
}

#[test]
fn since_ref_scopes_findings_list() {
    let (_tmp, workspace) = workspace_with_revision_findings();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, ShellCommand::Since("main".to_string()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert_eq!(app.findings().len(), 1);
    assert_eq!(app.findings()[0].rule_id, "demo.sql");
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "findings"
            && line.body.contains("branch:main")
            && line.body.contains("loaded 1 of 1 matching")
    }));
}

#[test]
fn since_ref_requires_target_before_filtering_findings() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::Since("main".to_string()));

    assert_ne!(app.shell_view(), ShellView::Workbench);
    assert!(app.findings().is_empty());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "error" && line.body.contains("since requires an active target")
    }));
}

fn workspace_with_revision_findings() -> (tempfile::TempDir, WorkspaceTarget) {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("scan-a", workspace.root(), "completed")
        .unwrap();
    store
        .record_run_started("scan-b", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding(
            "scan-a",
            &Finding::new_semgrep(
                "demo.sql",
                "src/db.ts",
                12,
                Some(12),
                Severity::High,
                "SQL injection in search",
            ),
        )
        .unwrap();
    store
        .insert_finding(
            "scan-b",
            &Finding::new_semgrep(
                "demo.token",
                "src/token.ts",
                2,
                Some(2),
                Severity::Low,
                "Hardcoded token",
            ),
        )
        .unwrap();
    kuzushi_core::write_run_summary(
        workspace.root(),
        &kuzushi_core::RunSummary::running(
            "scan-a",
            "scan",
            None,
            workspace.root().display().to_string(),
        )
        .with_target_git(Some(kuzushi_core::RunTargetGitMetadata {
            sha: "abcdef1234567890".to_string(),
            branch: Some("main".to_string()),
            dirty: true,
        })),
    )
    .unwrap();
    kuzushi_core::write_run_summary(
        workspace.root(),
        &kuzushi_core::RunSummary::running(
            "scan-b",
            "scan",
            None,
            workspace.root().display().to_string(),
        )
        .with_target_git(Some(kuzushi_core::RunTargetGitMetadata {
            sha: "9999991234567890".to_string(),
            branch: Some("release".to_string()),
            dirty: false,
        })),
    )
    .unwrap();
    (tmp, workspace)
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_triage_through_langgraph_runtime_bridge_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("triage".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint)),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
        .record_run_started("run-1", workspace.root(), "completed")
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("verify".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint)),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("VULNERABLE")));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("fixture marker path")));
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
        .record_run_started("run-1", workspace.root(), "completed")
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("patch".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"fingerprint":"{}","maxIterations":1,"buildCmd":"true","testCmd":"true"}}"#,
                finding.fingerprint
            )),
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("threat-model".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"outputDir":".kuzushi/tm"}"#.to_string()),
        },
    );
    drain_chain_with_auto_reuse(&mut app);

    // Auto-open lands on the Workbench DFD center once the threat model is built.
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);
    assert!(app.log_lines().iter().any(|line| {
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
        worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
        anthropic_oauth: None,
    };

    let mut app = ShellApp::new(config, Some(&workspace));
    run_command(&mut app, ShellCommand::Use("x-ray".to_string()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("x-ray:run".to_string()),
            input: None,
        },
    );
    drain_tool(&mut app);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
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
        .record_run_started("run-1", workspace.root(), "completed")
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
    run_command(
        &mut app,
        ShellCommand::Open(finding.fingerprint[..8].to_string()),
    );

    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| &finding.fingerprint),
        Some(&finding.fingerprint)
    );
}

#[test]
fn ctrl_c_requests_active_scan_abort_before_exit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(!app.should_quit());
    assert_eq!(
        app.scan().map(|scan| scan.stage.as_str()),
        Some("abort requested")
    );
    assert!(app.scan().is_some_and(|scan| scan.abort_requested));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "scan"
            && line.body.contains("abort requested")
            && line.body.contains("not claiming")
    }));
}

#[test]
fn threat_digit_hotkeys_switch_views_without_entering_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.threat_mut().open(ThreatView::Summary);
    app.set_shell_view(ShellView::Threat);

    // DFD moved to the Workbench; the remaining tabs renumber from 1, so
    // `1` is now STRIDE.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('1'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Threat);
    assert_eq!(app.router.threat().view(), ThreatView::Stride);
    assert!(app.input().is_empty());
}

#[test]
fn first_ctrl_c_at_idle_arms_without_quitting() {
    let mut app = ShellApp::new(V2Config::default(), None);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(!app.should_quit());
    assert!(app.ctrl_c_armed());
}

#[test]
fn ctrl_c_with_active_scan_returns_cancel_effect_without_aborting_inline() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
        ))),
    );

    assert!(result.changed);
    assert!(matches!(
        result.effects.as_slice(),
        [ShellEffect::CancelActiveJobs]
    ));
    assert!(!app.should_quit());
    assert!(!app.ctrl_c_armed());
    assert!(!cancel.is_cancelled());
    assert!(!app.scan().is_some_and(|scan| scan.abort_requested));

    EffectRuntime::execute(&mut app, result.effects);
    assert!(cancel.is_cancelled());
    assert!(app.scan().is_some_and(|scan| scan.abort_requested));
}

#[test]
fn second_ctrl_c_returns_shell_quit_effect_without_quitting_inline() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let first = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
        ))),
    );
    assert!(first.changed);
    assert!(first.effects.is_empty());
    assert!(app.ctrl_c_armed());

    let second = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
        ))),
    );

    assert!(second.changed);
    assert!(matches!(
        second.effects.as_slice(),
        [ShellEffect::RequestShellQuit]
    ));
    assert!(!app.should_quit());

    EffectRuntime::execute(&mut app, second.effects);
    assert!(app.should_quit());
}

#[test]
fn second_ctrl_c_within_window_quits() {
    let mut app = ShellApp::new(V2Config::default(), None);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(app.should_quit());
}

#[test]
fn ctrl_d_also_arms_and_quits() {
    let mut app = ShellApp::new(V2Config::default(), None);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
    );
    assert!(app.ctrl_c_armed());
    assert!(!app.should_quit());
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
    );
    assert!(app.should_quit());
}

#[test]
fn any_other_key_disarms() {
    let mut app = ShellApp::new(V2Config::default(), None);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(app.ctrl_c_armed());
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()),
    );
    assert!(!app.ctrl_c_armed());
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(!app.should_quit());
}

#[test]
fn arm_window_expires_via_tick() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_ctrl_c_armed_at(Some(
        Instant::now() - (CTRL_C_ARM_WINDOW + Duration::from_secs(1)),
    ));
    assert!(!app.ctrl_c_armed());
    app.tick();
    assert!(app.ctrl_c_armed_at().is_none());
}

#[test]
fn throttle_advisory_set_and_clear() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_throttle("openai", "429: backing off 2s");
    assert!(app.advisory().throttle.is_some());
    app.clear_throttle();
    assert!(app.advisory().throttle.is_none());
}

#[test]
fn throttle_advisory_expires_via_tick() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_throttle("openai", "stale");
    app.advisory_mut().throttle.as_mut().unwrap().since =
        Instant::now() - (THROTTLE_STALE_AFTER + Duration::from_secs(1));
    app.tick();
    assert!(app.advisory().throttle.is_none());
}

#[test]
fn scan_failure_sets_error_notice_and_keeps_log() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.apply_scan_failed("semgrep not found".to_string());

    let notice = app.advisory().notice.as_ref().expect("notice surfaced");
    assert_eq!(notice.severity, crate::NoticeSeverity::Error);
    assert!(notice.message.contains("semgrep not found"));
    assert!(
        app.log_lines().iter().any(|line| line.prefix == "error"),
        "transcript record must be preserved"
    );
}

#[test]
fn esc_dismisses_notice_before_going_back() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.set_error_notice("tool", "boom");

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert!(app.advisory().notice.is_none(), "notice dismissed");
    assert_eq!(
        app.shell_view(),
        ShellView::Tools,
        "back deferred to next Esc"
    );
}

#[test]
fn empty_back_stack_returns_to_workbench() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);

    app.go_back();

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn notice_auto_clears_after_stale_window() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_error_notice("tool", "stale");
    app.advisory_mut().notice.as_mut().unwrap().since =
        Instant::now() - (NOTICE_STALE_AFTER + Duration::from_secs(1));
    assert!(app.tick());
    assert!(app.advisory().notice.is_none());
}

#[test]
fn multiline_paste_sets_warn_notice() {
    let mut app = ShellApp::new(V2Config::default(), None);
    paste_text(&mut app, "first\nsecond\nthird");

    assert_eq!(app.input(), "first", "only the first line is kept");
    let notice = app
        .advisory()
        .notice
        .as_ref()
        .expect("paste notice surfaced");
    assert_eq!(notice.severity, crate::NoticeSeverity::Warn);
    assert!(notice.message.contains("dropped 2"));
}

#[test]
fn paste_of_workspace_file_attaches_instead_of_filling_prompt() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("docs")).unwrap();
    let path = temp.path().join("docs").join("design.md");
    std::fs::write(&path, "design notes").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    paste_text(&mut app, &path.display().to_string());

    assert!(app.input().is_empty());
    assert_eq!(app.shell_view(), ShellView::KnowledgeBase);
    assert_eq!(app.domain().kb_view().attachments.len(), 1);
    assert_eq!(
        app.domain().kb_view().attachments[0].source,
        "docs/design.md"
    );
}

#[test]
fn paste_of_workspace_file_returns_attach_effect_without_attaching_inline() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("docs")).unwrap();
    let path = temp.path().join("docs").join("design.md");
    std::fs::write(&path, "design notes").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Paste(path.display().to_string())),
    );

    assert!(result.changed);
    assert_eq!(app.input(), "");
    assert!(app.domain().kb_view().attachments.is_empty());
    assert_eq!(
        kb_attach_effect(&result.effects).map(|effect| effect.source.as_str()),
        Some("docs/design.md")
    );
}

#[test]
fn file_picker_filters_and_attaches_selected_workspace_file() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("docs")).unwrap();
    std::fs::write(temp.path().join("docs").join("design.md"), "design notes").unwrap();
    std::fs::write(temp.path().join("README.md"), "readme").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_file_picker();
    for ch in "des".chars() {
        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()),
        );
    }
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::KnowledgeBase);
    assert_eq!(app.domain().kb_view().attachments.len(), 1);
    assert_eq!(
        app.domain().kb_view().attachments[0].source,
        "docs/design.md"
    );
}

#[test]
fn file_picker_enter_returns_attach_effect_without_attaching_inline() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("docs")).unwrap();
    std::fs::write(temp.path().join("docs").join("design.md"), "design notes").unwrap();
    std::fs::write(temp.path().join("README.md"), "readme").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_file_picker();
    for ch in "des".chars() {
        update(
            &mut app,
            Msg::Term(TermEvent::Key(KeyEvent::new(
                KeyCode::Char(ch),
                KeyModifiers::empty(),
            ))),
        );
    }
    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    assert!(app.domain().kb_view().attachments.is_empty());
    assert_eq!(
        kb_attach_effect(&result.effects).map(|effect| effect.source.as_str()),
        Some("docs/design.md")
    );
}

#[test]
fn file_picker_close_returns_to_origin_without_readding_picker_history() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("README.md"), "readme").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);

    app.open_file_picker();
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    assert!(app
        .router
        .navigation()
        .contains_history(&ShellView::Workbench));

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    app.sync_view_change();
    assert!(!app
        .router
        .navigation()
        .contains_history(&ShellView::FilePicker));
}

#[test]
fn file_picker_command_reducer_defers_workspace_walk_to_effect_runtime() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("README.md"), "readme").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let effects = app
        .reduce_command_effects(&ShellCommand::FilePicker)
        .expect("file picker command should be effect-routed");

    assert!(matches!(effects.as_slice(), [ShellEffect::OpenFilePicker]));
    assert_ne!(app.shell_view(), ShellView::FilePicker);
    assert!(app.router.file_picker().files().is_empty());

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.shell_view(), ShellView::FilePicker);
    assert!(app
        .router
        .file_picker()
        .files()
        .contains(&"README.md".to_string()));
}

#[test]
fn map_phase_attach_row_opens_file_picker() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("README.md"), "readme").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_phase_picker(WorkflowPhase::Map);
    let cursor = app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .position(|row| row.id == PlanningTaskId::AttachFiles)
        .expect("attach files row");
    app.engagement.planning_picker_mut().set_cursor(cursor);
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .insert(PlanningTaskId::AttachFiles);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::FilePicker);
    assert!(app
        .router
        .file_picker()
        .files()
        .contains(&"README.md".to_string()));
}

#[test]
fn skipped_map_phase_attach_row_does_not_intercept_enter() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("README.md"), "readme").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_phase_picker(WorkflowPhase::Map);
    let cursor = app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .position(|row| row.id == PlanningTaskId::AttachFiles)
        .expect("attach files row");
    app.engagement.planning_picker_mut().set_cursor(cursor);
    app.engagement.planning_picker_mut().selected_mut().clear();
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .insert(PlanningTaskId::GatherRepoContext);
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .remove(&PlanningTaskId::AttachFiles);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(app.engagement.running_tool(), Some("context:build"));
    drain_tool(&mut app);
}

#[test]
fn enter_on_empty_findings_logs_guidance() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    assert!(app.findings().is_empty());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.prefix == "findings" && line.body.contains("run `scan`")),
        "empty-findings Enter should guide the operator"
    );
    assert_eq!(app.shell_view(), ShellView::Workbench, "stay on the view");
}

#[test]
fn open_start_view_lands_on_the_workbench_by_default() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);
    open_start_view(&mut app);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn open_start_view_preserves_an_active_onboarding_picker() {
    // The launch landing must never clobber a first-run gate.
    for picker in [
        ShellView::ModelPicker,
        ShellView::TargetPicker,
        ShellView::PlanningPicker,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(picker.clone());
        open_start_view(&mut app);
        assert_eq!(app.shell_view(), picker, "picker was clobbered");
    }
}

#[test]
fn fresh_target_can_auto_open_the_phase_picker() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));

    app.open_fresh_planner_or_workbench();

    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
}

#[test]
fn returning_target_lands_on_workbench_instead_of_phase_picker() {
    let dir = tempfile::tempdir().expect("temp target");
    kuzushi_core::write_run_summary(
        dir.path(),
        &kuzushi_core::RunSummary::running(
            "scan-clean",
            "scan",
            None,
            dir.path().display().to_string(),
        )
        .complete()
        .with_findings(Some(0)),
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));

    app.open_fresh_planner_or_workbench();

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn target_with_persisted_findings_lands_on_workbench_instead_of_phase_picker() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    seed_true_positive_finding(&workspace);
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));

    app.open_fresh_planner_or_workbench();

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn shell_start_with_persisted_findings_lands_on_workbench() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    seed_true_positive_finding(&workspace);
    let mut config = V2Config::default();
    config.model = Some("local:test".to_string());
    let mut app = ShellApp::new(config, Some(&workspace));

    assert!(!app.findings().is_empty());
    assert_ne!(app.shell_view(), ShellView::PlanningPicker);

    open_start_view(&mut app);

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn reverse_search_finds_and_accepts_a_past_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_command_history(vec!["scan .".to_string(), "run semgrep:scan".to_string()]);

    // Ctrl+R enters search; typing narrows to the matching command.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
    );
    assert!(app.history_search().is_some());
    for ch in "semgrep".chars() {
        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()),
        );
    }
    assert_eq!(app.current_history_match(), Some("run semgrep:scan"));

    // Enter accepts the match into the prompt and exits search.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert!(app.history_search().is_none());
    assert_eq!(app.input(), "run semgrep:scan");
}

#[test]
fn reverse_search_esc_cancels() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_command_history(vec!["scan .".to_string()]);
    app.enter_history_search();
    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.history_search().is_none());
    assert!(app.input().is_empty());
}

#[test]
fn ctrl_c_in_reverse_search_still_cancels_running_tool() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_command_history(vec!["run triage:run".to_string()]);
    app.enter_history_search();
    app.set_running_tool_for_test("triage:run");
    app.set_tool_cancel_for_test(cancel.clone());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(app.history_search().is_none());
    assert!(app.tool_abort_requested());
    assert!(cancel.is_cancelled());
    assert!(!app.ctrl_c_armed());
    assert!(!app.should_quit());
}

#[test]
fn command_palette_opens_filters_and_loads_without_executing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);

    // Ctrl+G opens the palette.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.shell_view(), ShellView::CommandPalette);

    // Typing filters the specs.
    for ch in "scan".chars() {
        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()),
        );
    }
    let matches = app.palette_matches();
    assert!(
        matches.iter().any(|spec| spec.command.starts_with("scan")),
        "query `scan` should surface the scan command"
    );

    // Enter loads the canonical head into the prompt but does NOT execute.
    let before_log = app.log_len();
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert_ne!(
        app.shell_view(),
        ShellView::CommandPalette,
        "palette closed"
    );
    assert!(
        !app.input().is_empty(),
        "selected command loaded into prompt"
    );
    assert!(
        !app.log_lines()
            .iter()
            .skip(before_log)
            .any(|line| line.prefix == ">"),
        "accepting must not submit the command"
    );
}

#[test]
fn command_palette_esc_closes_without_loading() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);
    app.open_command_palette();
    assert_eq!(app.shell_view(), ShellView::CommandPalette);

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_ne!(app.shell_view(), ShellView::CommandPalette);
    assert!(
        app.input().is_empty(),
        "Esc cancels without loading a command"
    );
}

#[test]
fn subverb_query_lists_subverbs_without_routing_to_unknown() {
    let mut app = ShellApp::new(V2Config::default(), None);
    submit_shell_line(&mut app, "task ?");

    let listed = app
        .log_lines()
        .iter()
        .find(|line| line.prefix == "task")
        .expect("task sub-verbs listed");
    assert!(listed.body.contains("block") && listed.body.contains("mode"));
    assert!(
        !app.log_lines()
            .iter()
            .any(|line| line.body.contains("unknown command")),
        "`task ?` must not fall through to the unknown-command path"
    );
}

#[test]
fn command_history_round_trips_to_disk_per_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));

    submit_shell_line(&mut app, "modules");
    submit_shell_line(&mut app, "tools");

    let path = tmp.path().join(".kuzushi/v3/shell-history.txt");
    assert!(path.exists(), "history file should be written");
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("modules") && contents.contains("tools"));

    let mut reopened = ShellApp::new(V2Config::default(), None);
    reopened.set_target(Some(tmp.path().to_path_buf()));
    reopened.load_persisted_history();
    assert_eq!(
        reopened.command_history(),
        ["modules".to_string(), "tools".to_string()]
    );
}

#[test]
fn history_load_caps_at_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(".kuzushi/v3/shell-history.txt");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let lines: Vec<String> = (0..(COMMAND_HISTORY_CAP + 50))
        .map(|i| format!("cmd-{i}"))
        .collect();
    std::fs::write(&path, lines.join("\n")).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.load_persisted_history();

    assert_eq!(app.command_history().len(), COMMAND_HISTORY_CAP);
    assert_eq!(app.command_history().last().unwrap(), "cmd-249");
}

#[test]
fn history_without_workspace_stays_in_memory_only() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(app.target().is_none());
    submit_shell_line(&mut app, "modules");
    // No panic, no disk write; history is still tracked in memory.
    assert_eq!(app.command_history(), ["modules".to_string()]);
}

#[test]
fn spinner_resets_when_work_completes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_spinner_phase_for_test(5);
    assert!(!app.has_running_work());
    assert!(app.tick(), "completion should force one repaint");
    assert_eq!(app.ui().spinner_phase(), 0);
}

#[test]
fn running_work_shows_strip_spinner_off_activity_view() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_running_tool_for_test("semgrep:scan");
    app.set_shell_view(ShellView::Catalog);

    let model = crate::ui_view_models::context_strip_model(&app);
    let run = model.run.expect("a run segment with a spinner");
    assert!(run.value.contains("semgrep:scan"));
    assert!(run.value.contains(app.spinner_glyph()));
}

#[test]
fn budget_halt_triggers_when_cost_exceeds_cap() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(0.10));
    app.record_cost(0.12);
    assert!(app.is_budget_halted());
    let halt = app.advisory().budget_halt.as_ref().unwrap();
    assert!(halt.spent_usd >= 0.12);
    assert_eq!(halt.limit_usd, 0.10);
}

#[test]
fn shell_uses_operator_budget_and_trusted_workflow_from_config() {
    let mut config = V2Config::default();
    config.operator.session_budget_usd = Some(1.25);
    config.operator.trusted_workflow_auto_accept = true;

    let app = ShellApp::new(config, None);

    assert_eq!(app.session().session_budget_usd(), Some(1.25));
    assert!(app.session().trusted_workflow_auto_accept());
}

#[test]
fn next_command_opens_phase_picker_at_derived_phase() {
    // `next` resumes the engagement wherever the workspace actually is —
    // fresh target lands in 組 map, map artifacts move it to 崩 hunt,
    // unconfirmed findings to 作 confirm, fully confirmed to 掛 fix.
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));

    run_command(&mut app, ShellCommand::Next);
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));

    std::fs::create_dir_all(dir.path().join(".kuzushi")).expect("kuzushi dir");
    std::fs::write(dir.path().join(".kuzushi/context-snapshot.json"), "{}")
        .expect("context snapshot");
    app.engagement.clear_phase();
    run_command(&mut app, ShellCommand::Next);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Hunt));

    *app.findings_mut() = vec![make_finding(Severity::High, "fp-journey", "Unconfirmed")];
    app.engagement.clear_phase();
    run_command(&mut app, ShellCommand::Next);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Confirm));

    app.findings_mut()[0].triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.9,
        rationale: "confirmed".to_string(),
        cost_usd: 0.0,
    });
    app.engagement.clear_phase();
    run_command(&mut app, ShellCommand::Next);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Fix));
}

#[test]
fn phase_command_opens_requested_phase_picker() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));

    run_command(&mut app, ShellCommand::Phase(WorkflowPhase::Confirm));

    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Confirm));
    assert!(app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .all(|row| row.id.phase() == WorkflowPhase::Confirm));
}

#[test]
fn phase_stop_after_config_blocks_later_phase_picker() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    let mut config = V2Config::default();
    config.phases.stop_after = Some(kuzushi_core::GuidedPhase::Map);
    let mut app = ShellApp::new(config, Some(&workspace));
    app.set_shell_view(ShellView::Catalog);
    app.engagement.clear_phase();

    app.open_phase_picker(WorkflowPhase::Hunt);

    assert_ne!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "phase"
            && line
                .body
                .contains("hunt stopped by config phases.stop_after=map")
    }));
}

#[test]
fn planning_phase_navigation_clamps_at_rail_edges() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.open_phase_picker(WorkflowPhase::Map);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('h'), KeyModifiers::empty()),
    );
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "phase" && line.body.contains("already at 組 KUMI-KATA") }));

    app.open_phase_picker(WorkflowPhase::Fix);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('l'), KeyModifiers::empty()),
    );
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Fix));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "phase" && line.body.contains("already at 掛 KAKE") }));
}

#[test]
fn planning_phase_navigation_moves_horizontally_without_running() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.open_phase_picker(WorkflowPhase::Confirm);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('h'), KeyModifiers::empty()),
    );
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Hunt));
    assert!(app.engagement.planning_queues_empty());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Right, KeyModifiers::empty()),
    );
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Confirm));
    assert!(app.engagement.planning_queues_empty());
}

#[test]
fn planning_phase_navigation_logs_config_block_instead_of_silent_noop() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    let mut config = V2Config::default();
    config.phases.stop_after = Some(kuzushi_core::GuidedPhase::Map);
    let mut app = ShellApp::new(config, Some(&workspace));
    app.open_phase_picker(WorkflowPhase::Map);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('l'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "phase" && line.body.contains("hunt stopped by config") }));
}

#[test]
fn hunt_phase_hides_systems_rows_for_plain_source_targets() {
    let dir = tempfile::tempdir().expect("temp target");
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/app.ts"), "export const ok = true;\n").unwrap();
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_phase_picker(WorkflowPhase::Hunt);

    let tasks: BTreeSet<PlanningTaskId> = app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .map(|row| row.id)
        .collect();
    assert!(tasks.contains(&PlanningTaskId::ScanAgenticSast));
    assert!(!tasks.contains(&PlanningTaskId::HuntSystems));
    assert!(!tasks.contains(&PlanningTaskId::HuntUseAfterFree));
}

#[test]
fn hunt_phase_keeps_systems_hunt_for_rust_but_hides_c_uaf() {
    let dir = tempfile::tempdir().expect("temp target");
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_phase_picker(WorkflowPhase::Hunt);

    let tasks: BTreeSet<PlanningTaskId> = app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .map(|row| row.id)
        .collect();
    assert!(tasks.contains(&PlanningTaskId::HuntSystems));
    assert!(!tasks.contains(&PlanningTaskId::HuntUseAfterFree));
}

#[test]
fn hunt_phase_keeps_c_family_specific_hunts_for_cpp_source() {
    let dir = tempfile::tempdir().expect("temp target");
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join("src/main.cpp"),
        "int main() { return 0; }\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_phase_picker(WorkflowPhase::Hunt);

    let tasks: BTreeSet<PlanningTaskId> = app
        .engagement
        .planning_picker()
        .tasks()
        .iter()
        .map(|row| row.id)
        .collect();
    assert!(tasks.contains(&PlanningTaskId::HuntSystems));
    assert!(tasks.contains(&PlanningTaskId::HuntUseAfterFree));
}

#[test]
fn target_picker_enter_applies_candidate_and_leaves_the_picker() {
    // Bare interactive `kuzushi` opens the target picker; Enter must wire
    // the chosen directory exactly like the `target <path>` verb and then
    // continue the first-run chain (never staying in the picker).
    let dir = tempfile::tempdir().expect("temp target");
    let submodule_path = dir.path().join("libs/parser");
    std::fs::create_dir_all(&submodule_path).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .target_picker_mut()
        .open(vec![crate::app::TargetCandidate {
            path: submodule_path.clone(),
            label: "libs/parser".to_string(),
            hint: "git submodule",
            scope: Some(crate::app::TargetCandidateScope {
                id: "submodule-libs-parser".to_string(),
                kind: kuzushi_core::NestedProjectKind::Submodule,
                rel_path: "libs/parser".to_string(),
            }),
        }]);
    app.router.target_picker_mut().set_cursor(0);
    app.set_shell_view(ShellView::TargetPicker);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert!(app.target().is_some(), "target applied from the picker");
    let canonical_submodule = std::fs::canonicalize(&submodule_path).unwrap();
    assert_eq!(app.target(), Some(canonical_submodule.as_path()));
    assert_eq!(
        app.active_scope().map(|scope| scope.id.as_str()),
        Some("submodule-libs-parser")
    );
    assert_ne!(app.shell_view(), ShellView::TargetPicker);
}

#[test]
fn target_picker_d_starts_the_offline_fixture() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::TargetPicker);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::empty()),
    );

    assert!(
        app.target().is_some(),
        "demo fixture target should be active"
    );
    assert_ne!(app.shell_view(), ShellView::TargetPicker);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("offline fixture ready")));
}

#[test]
fn target_activation_applies_ready_default_model_before_onboarding_continues() {
    let _env_lock = env_test_lock();
    let _openai_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let _anthropic_key = EnvVarGuard::unset("ANTHROPIC_API_KEY");
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(
        &mut app,
        ShellCommand::Target(Some(dir.path().display().to_string())),
    );

    assert!(app.config().model.is_some());
    assert_ne!(app.shell_view(), ShellView::ModelPicker);
}

#[test]
fn target_picker_esc_defers_to_workbench_without_a_target() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.target_picker_mut().open(Vec::new());
    app.set_shell_view(ShellView::TargetPicker);

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert!(app.target().is_none());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("browsing without a target")));
}

#[test]
fn scan_completion_raises_success_banner_when_operator_is_elsewhere() {
    // Ambient-progress story: background work must announce itself when it
    // lands while the operator is on another view — and stay quiet when
    // they're already watching the Activity feed.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(ActivitySession::new("r-scan")));
    app.set_shell_view(ShellView::Workbench);
    let effects = app.apply_scan_finished("r-scan".to_string(), 3);
    EffectRuntime::execute(&mut app, effects);
    let notice = app.advisory().notice.clone().expect("completion banner");
    assert_eq!(notice.severity, NoticeSeverity::Success);
    assert!(notice.message.contains("3 findings"), "{}", notice.message);
    assert!(notice.message.contains("`findings`"), "{}", notice.message);

    app.advisory_mut().notice = None;
    app.set_activity(Some(ActivitySession::new("r-scan2")));
    app.set_shell_view(ShellView::Activity);
    let effects = app.apply_scan_finished("r-scan2".to_string(), 1);
    EffectRuntime::execute(&mut app, effects);
    assert!(
        app.advisory().notice.is_none(),
        "no banner while watching the feed"
    );
}

#[test]
fn finished_scan_marks_never_started_activity_tasks_not_run() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut session = ActivitySession::new("r-scan");
    let mut active = DagTaskRow::queued("triage:run".to_string(), "triage".to_string(), Vec::new());
    active.state = DagTaskState::Active;
    active.started_at = Some(std::time::Instant::now());
    session.tasks.insert(active.task_id.clone(), active);
    session.tasks.insert(
        "patch:finding".to_string(),
        DagTaskRow::queued("patch:finding".to_string(), "patch".to_string(), Vec::new()),
    );
    app.set_activity(Some(session));

    let effects = app.apply_scan_finished("r-scan".to_string(), 0);
    EffectRuntime::execute(&mut app, effects);

    let session = app.activity().expect("activity session");
    assert_eq!(session.tasks["triage:run"].state, DagTaskState::Done);
    let skipped = &session.tasks["patch:finding"];
    assert_eq!(skipped.state, DagTaskState::Skipped);
    assert_eq!(skipped.last_label, "not run in this scan");
}

#[test]
fn zero_finding_scan_does_not_rewind_confirm_or_fix_phase() {
    for phase in [WorkflowPhase::Confirm, WorkflowPhase::Fix] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.engagement.set_phase(phase);
        app.set_activity(Some(ActivitySession::new("r-scan")));

        let effects = app.apply_scan_finished("r-scan".to_string(), 0);
        EffectRuntime::execute(&mut app, effects);

        assert_eq!(app.engagement.current_phase(), Some(phase));
    }
}

#[test]
fn scene_view_is_never_a_trap() {
    // /scene used to eat h/j/k/l (camera orbit) even mid-word, making
    // `back` and `home` untypeable on the default 3D page, and Esc with a
    // half-typed prompt toggled clear/restore forever. The gallery must
    // always be exitable: Esc and q leave directly, and typing yields the
    // hotkeys to the prompt.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    run_command(&mut app, ShellCommand::Scene);
    app.sync_view_change();
    assert!(matches!(app.shell_view(), ShellView::Scene));
    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!matches!(app.shell_view(), ShellView::Scene), "Esc exits");

    run_command(&mut app, ShellCommand::Scene);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty()),
    );
    assert!(!matches!(app.shell_view(), ShellView::Scene), "q exits");

    run_command(&mut app, ShellCommand::Scene);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );
    assert!(
        matches!(app.shell_view(), ShellView::Scene),
        "o is not a scene exit alias"
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()),
    );
    assert!(
        matches!(app.shell_view(), ShellView::Scene),
        "n is not a scene paging alias"
    );
    assert_eq!(app.input(), "on");
    app.clear_input();
    app.set_cursor(0);

    // Typing a command containing orbit keys must reach the prompt intact.
    for ch in "back".chars() {
        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()),
        );
    }
    assert_eq!(
        app.input(),
        "back",
        "orbit keys yield to a non-empty prompt"
    );

    app.clear_input();
    app.set_cursor(0);
    run_command(&mut app, ShellCommand::Scene);
    app.set_input("/");
    app.set_cursor(1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );
    assert!(matches!(app.shell_view(), ShellView::Scene));
    assert_eq!(app.input(), "/o", "o yields to a non-empty prompt");
}

#[test]
fn static_scene_pages_do_not_consume_3d_only_controls() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::Dfd);
    app.set_shell_view(ShellView::Scene);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()),
    );

    assert_eq!(app.input(), "pr");
    assert!(!app.router.scene().paused());
}

#[test]
fn next_command_without_target_logs_guidance() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let view_before = app.shell_view().clone();
    run_command(&mut app, ShellCommand::Next);
    assert_eq!(app.shell_view(), view_before);
    assert!(app
        .log_lines()
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
        ..Finding::default()
    }
}

fn make_projected_duplicate(severity: Severity, fp: &str, title: &str) -> Finding {
    let mut finding = make_finding(severity, fp, title);
    finding.dedup_key = Some("engagement:shared".to_string());
    finding
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
        (HotkeyTrigger::BackTab, KeyCode::BackTab),
        (HotkeyTrigger::Esc, KeyCode::Esc),
        (HotkeyTrigger::PageUp, KeyCode::PageUp),
        (HotkeyTrigger::PageDown, KeyCode::PageDown),
        (HotkeyTrigger::Up, KeyCode::Up),
        (HotkeyTrigger::Down, KeyCode::Down),
        (HotkeyTrigger::Left, KeyCode::Left),
        (HotkeyTrigger::Right, KeyCode::Right),
    ];
    NON_CHAR_CODES
        .iter()
        .find_map(|(candidate, code)| (*candidate == trigger).then_some(*code))
        .unwrap_or(KeyCode::Null)
}

fn app_with_findings(count: usize) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    *app.findings_mut() = (0..count)
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
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: if paused { "paused" } else { "running" }.to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_shell_view(ShellView::ModuleRun);
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
fn tune_show_local_reducer_returns_show_effect_without_reading_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::Tune);
    let path = temp.path().join(".kuzushi/house-rules/sast.md");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "focus on auth bypass").unwrap();

    let update = app.reduce_submitted_line("show");
    let show = house_rules_show_effect(&update.effects).expect("house rules show effect");

    assert!(update.handled);
    assert_eq!(show.path.as_deref(), Some(path.as_path()));
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body == "house rules:"));

    EffectRuntime::execute(&mut app, update.effects);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body == "house rules:"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body == "focus on auth bypass"));
}

#[test]
fn tune_set_local_reducer_returns_write_effect_without_touching_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::Tune);

    let update = app.reduce_submitted_line("set \"focus on auth bypass\"");
    let path = temp.path().join(".kuzushi/house-rules/sast.md");
    let write = house_rules_write_effect(&update.effects).expect("house rules write effect");

    assert!(update.handled);
    assert_eq!(write.path, path);
    assert_eq!(write.value, "focus on auth bypass");
    assert!(!path.exists());

    EffectRuntime::execute(&mut app, update.effects);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "focus on auth bypass"
    );
}

#[test]
fn tune_reset_local_reducer_returns_reset_effect_without_touching_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::Tune);
    let path = temp.path().join(".kuzushi/house-rules/sast.md");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "focus on auth bypass").unwrap();

    let update = app.reduce_submitted_line("reset");
    let reset = house_rules_reset_effect(&update.effects).expect("house rules reset effect");

    assert!(update.handled);
    assert_eq!(reset.path, path);
    assert!(path.exists());

    EffectRuntime::execute(&mut app, update.effects);
    assert!(!path.exists());
}

#[test]
fn tune_set_writes_house_rules_and_reset_removes_them() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::Tune);
    submit_shell_line(&mut app, "set \"focus on auth bypass\"");
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
    submit_shell_line(&mut app, "reset");
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
        .log_lines()
        .iter()
        .filter(|line| line.prefix == "quickstart")
        .count();
    run_command(&mut app, ShellCommand::Quickstart);
    assert_eq!(app.shell_view(), ShellView::Quickstart);
    let new_lines: Vec<_> = app
        .log_lines()
        .iter()
        .filter(|line| line.prefix == "quickstart")
        .skip(baseline_quickstart_lines)
        .collect();
    assert_eq!(new_lines.len(), 1, "expected exactly one transcript line");
    assert!(new_lines[0].body.contains("target .; next -> findings"));
}

#[test]
fn startup_logs_first_finding_path_for_bare_shell() {
    let app = ShellApp::new(V2Config::default(), None);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "startup" && line.body.contains("modules")));
    let help = app
        .log_lines()
        .iter()
        .find(|line| line.prefix == "help")
        .expect("startup help line");
    assert!(help.body.contains("next"));
    assert!(help.body.contains("guided workflow"));
    // P1-3: the first-finding hint is rendered in the catalog body,
    // not duplicated into the 2-row transcript. Confirm the helper
    // still produces the correct command so `next_action_line` has
    // something to render.
    assert_eq!(app.first_finding_scan_command(), "target .; next");
    let hint = app.first_finding_hint();
    assert!(hint.contains("target .; next"));
    assert!(hint.contains("findings"));
    assert!(
        !app.log_lines()
            .iter()
            .any(|line| line.prefix == "first-run"),
        "transcript should no longer carry a first-run dup of the catalog hint"
    );
}

#[test]
fn startup_logs_active_target_first_finding_path() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let app = ShellApp::new(V2Config::default(), Some(&workspace));
    assert_eq!(app.first_finding_scan_command(), "next");
    let hint = app.first_finding_hint();
    assert!(hint.contains("next"));
    assert!(!hint.contains("scan ."));
    assert!(hint.contains("findings"));
}

#[test]
fn target_command_switches_target_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("vendor")).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let path_str = temp.path().to_string_lossy().to_string();
    run_command(&mut app, ShellCommand::Target(Some(path_str.clone())));
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    assert_eq!(app.target(), Some(canonical.as_path()));
    let scope_tree = kuzushi_core::load_nested_project_scopes(temp.path())
        .unwrap()
        .expect("persisted scope tree");
    assert!(scope_tree
        .scopes
        .iter()
        .any(|scope| scope.rel_path == "vendor"));
    assert_eq!(
        app.active_scope().map(|scope| scope.id.as_str()),
        Some(kuzushi_core::workspace::ROOT_SCOPE_ID)
    );
    // When called with no path, should report the current target.
    run_command(&mut app, ShellCommand::Target(None));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "target" && line.body.contains("current target")));
}

#[test]
fn target_command_reducer_returns_activation_effect_without_touching_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("app");
    std::fs::create_dir(&target).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);

    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::Target(Some(
            target.to_string_lossy().to_string(),
        ))),
    );

    assert!(result.changed);
    let activation = target_activation_effect(&result.effects).expect("target activation effect");
    assert_eq!(activation.path, target);
    assert!(activation.selected_scope.is_none());
    assert!(matches!(activation.source, TargetActivationSource::Command));
    assert!(app.target().is_none());
    assert!(!target.join(".kuzushi").exists());

    EffectRuntime::execute(&mut app, result.effects);

    let canonical = std::fs::canonicalize(&target).unwrap();
    assert_eq!(app.target(), Some(canonical.as_path()));
    assert!(target.join(".kuzushi").exists());
}

#[test]
fn component_command_reducer_returns_selection_effect_without_reading_scope_tree() {
    let temp = tempfile::tempdir().unwrap();
    let component_root = temp.path().join("packages/api");
    std::fs::create_dir_all(&component_root).unwrap();
    std::fs::write(component_root.join("package.json"), "{}").unwrap();
    std::fs::create_dir(component_root.join("src")).unwrap();
    std::fs::write(component_root.join("src/index.js"), "export default 1;\n").unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let scope_tree = kuzushi_core::discover_and_save_nested_project_scopes(temp.path()).unwrap();
    assert!(scope_tree
        .scopes
        .iter()
        .any(|scope| scope.rel_path == "packages/api"));
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_active_scope(None);

    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::Component(Some("packages/api".to_string()))),
    );

    assert!(result.changed);
    let [ShellEffect::SelectComponent(selection)] = result.effects.as_slice() else {
        panic!("component command should return a selection effect");
    };
    assert_eq!(selection.target.as_deref(), Some(workspace.root()));
    assert_eq!(selection.raw.as_deref(), Some("packages/api"));
    assert_eq!(app.active_scope(), None);
    assert_ne!(app.shell_view(), ShellView::Workbench);

    EffectRuntime::execute(&mut app, result.effects);

    assert_eq!(
        app.active_scope().map(|scope| scope.rel_path.as_str()),
        Some("packages/api")
    );
    assert_eq!(app.shell_view(), ShellView::Workbench);
}

#[test]
fn target_activation_effect_defers_findings_and_scope_reload_to_followups() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("app");
    std::fs::create_dir(&target).unwrap();
    let workspace = WorkspaceTarget::new(&target).unwrap();
    seed_true_positive_finding(&workspace);
    fs::write(
        target.join(".kuzushi/scope.toml"),
        "[in_scope]\nhosts = [\"*.example.com\"]\n[out_of_scope]\nhosts = []\n",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);

    let effects = app.activate_target_effect(TargetActivation {
        path: target.clone(),
        selected_scope: None,
        source: TargetActivationSource::Command,
    });

    let canonical = std::fs::canonicalize(&target).unwrap();
    assert_eq!(app.target(), Some(canonical.as_path()));
    assert!(app.findings().is_empty(), "findings reload ran inline");
    assert!(
        app.domain().program_scope().is_none(),
        "program scope reload ran inline"
    );
    assert!(silent_findings_refresh_effect(&effects));
    assert!(program_scope_refresh_effect(&effects));

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.findings().len(), 1);
    assert!(app.domain().program_scope().is_some());
}

#[test]
fn target_command_resumes_onboarding_after_deferred_picker() {
    let _env_lock = env_test_lock();
    let _skip_guard = EnvVarGuard::unset("KUZUSHI_SKIP_ONBOARDING");
    let _openai_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let _anthropic_key = EnvVarGuard::unset("ANTHROPIC_API_KEY");
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);

    run_command(
        &mut app,
        ShellCommand::Target(Some(temp.path().to_string_lossy().to_string())),
    );

    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    assert_eq!(app.target(), Some(canonical.as_path()));
    assert!(app.config().model.is_some());
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
}

#[test]
fn run_diff_command_opens_revision_comparison_view() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(
        &mut app,
        ShellCommand::RunDiff {
            left: "run-left".to_string(),
            right: "run-right".to_string(),
        },
    );

    assert_eq!(app.shell_view(), ShellView::RunDiff);
    assert_eq!(app.router.run_diff().left(), "run-left");
    assert_eq!(app.router.run_diff().right(), "run-right");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "runs" && line.body.contains("run-left -> run-right")));
}

#[cfg(unix)]
#[test]
fn target_revision_reducer_returns_switch_effect_without_running_git() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    let result = update(
        &mut app,
        Msg::Cmd(ShellCommand::TargetRevision("HEAD~1".to_string())),
    );

    assert!(result.changed);
    let switch = target_revision_switch_effect(&result.effects).expect("revision switch effect");
    assert_eq!(switch.target, workspace.root());
    assert_eq!(switch.reference, "HEAD~1");
    assert!(app
        .log_lines()
        .iter()
        .all(|line| !line.body.contains("revision switch blocked")));
}

#[cfg(unix)]
#[test]
fn target_revision_effect_defers_findings_and_scope_reload_to_followups() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().to_path_buf();
    fs::write(repo.join("tracked.txt"), "first\n").unwrap();
    init_git_repo(&repo);
    let first = git_head(&repo);
    fs::write(repo.join("tracked.txt"), "second\n").unwrap();
    git(&repo, &["add", "tracked.txt"]);
    git(&repo, &["commit", "-m", "second"]);

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    seed_true_positive_finding(&workspace);
    fs::write(
        repo.join(".kuzushi/scope.toml"),
        "[in_scope]\nhosts = [\"*.example.com\"]\n[out_of_scope]\nhosts = []\n",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.domain_mut().set_findings(Vec::new());
    app.domain_mut().set_program_scope(None);

    let effects = app.switch_target_revision_effect(TargetRevisionSwitch {
        target: repo.clone(),
        reference: first.clone(),
    });

    assert_eq!(git_head(&repo), first);
    assert!(app.findings().is_empty(), "findings reload ran inline");
    assert!(
        app.domain().program_scope().is_none(),
        "program scope reload ran inline"
    );
    assert!(silent_findings_refresh_effect(&effects));
    assert!(program_scope_refresh_effect(&effects));

    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.findings().len(), 1);
    assert!(app.domain().program_scope().is_some());
}

#[cfg(unix)]
#[test]
fn target_revision_command_switches_clean_git_target() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().to_path_buf();
    fs::write(repo.join("tracked.txt"), "first\n").unwrap();
    init_git_repo(&repo);
    let first = git_head(&repo);
    fs::write(repo.join("tracked.txt"), "second\n").unwrap();
    git(&repo, &["add", "tracked.txt"]);
    git(&repo, &["commit", "-m", "second"]);

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    run_command(&mut app, ShellCommand::TargetRevision(first.clone()));

    assert_eq!(git_head(&repo), first);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "target" && line.body.contains("switched revision") }));
}

#[test]
fn bracketed_paste_single_line_inserts_text_without_submit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('h'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('i'), KeyModifiers::empty()),
    );
    // Single-line pastes insert verbatim — Enter is NOT synthesized.
    paste_text(&mut app, " world");
    assert_eq!(app.input(), "hi world");
    assert_eq!(app.cursor(), app.input().chars().count());
    // Pressing Enter after a paste submits the line normally.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert!(app.input().is_empty());
}

#[test]
fn multi_line_paste_keeps_first_line_and_warns() {
    // Pasting 3 lines should not auto-submit each one — the shell is a
    // single-command-per-Enter prompt and submitting `rm` from a pasted
    // snippet would be catastrophic. Keep the first line, warn the user,
    // let them review and submit explicitly.
    let mut app = ShellApp::new(V2Config::default(), None);
    paste_text(&mut app, "first\r\nsecond\nthird");
    assert_eq!(app.input(), "first");
    assert_eq!(app.cursor(), "first".chars().count());
    let advisory = app
        .log_lines()
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
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    *app.findings_mut() = vec![
        make_finding(Severity::High, "f1", "a"),
        make_finding(Severity::High, "f2", "b"),
        make_finding(Severity::High, "f3", "c"),
    ];

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 2);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.findings().cursor(),
        2,
        "j should clamp at last row"
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 0);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 2);
}

#[test]
fn findings_cursor_follows_selected_fingerprint_in_alias_order() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let selected = make_finding(Severity::High, "fp-high", "selected");
    *app.findings_mut() = vec![
        selected.clone(),
        make_finding(Severity::Critical, "fp-critical", "first"),
    ];
    *app.selected_finding_mut() = Some(selected);
    app.router.findings_mut().set_cursor(0);

    app.sync_findings_cursor_to_selected();

    assert_eq!(app.router.findings().cursor(), 1);
}

#[test]
fn findings_cursor_follows_selected_engagement_key_in_projected_order() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let selected = make_projected_duplicate(Severity::Medium, "fp-duplicate-medium", "selected");
    *app.findings_mut() = vec![
        selected.clone(),
        make_projected_duplicate(Severity::High, "fp-duplicate-high", "representative"),
        make_finding(Severity::Low, "fp-distinct-low", "distinct"),
    ];
    *app.selected_finding_mut() = Some(selected);
    app.router.findings_mut().set_cursor(1);

    app.sync_findings_cursor_to_selected();

    assert_eq!(app.router.findings().cursor(), 0);
}

#[test]
fn mouse_wheel_moves_findings_cursor_without_empty_underflow() {
    let mut app = app_with_findings(5);
    app.router.findings_mut().set_cursor(1);

    mouse_event(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.router.findings().cursor(), 2);

    mouse_event(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.router.findings().cursor(), 1);
}

#[test]
fn mouse_wheel_scrolls_focused_workbench_pane_by_one_line() {
    let mut app = app_with_findings(5);
    app.router.workbench_mut().set_focus(WorkbenchPane::Details);

    mouse_event(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.router.workbench().scroll().details, 1);

    mouse_event(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.router.workbench().scroll().details, 0);
}

#[test]
fn mouse_click_focuses_activity_panes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    let mut session = ActivitySession::new("run-live");
    session.tasks.insert(
        "triage:run".to_string(),
        DagTaskRow::queued("triage:run".to_string(), "triage".to_string(), Vec::new()),
    );
    app.set_activity(Some(session));

    mouse_event(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: 1,
            row: 4,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.router.activity().pane_focus, PaneFocus::Left);

    let width = crossterm::terminal::size()
        .map(|(width, _)| width)
        .unwrap_or(160);
    mouse_event(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: width.saturating_sub(1),
            row: 4,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.router.activity().pane_focus, PaneFocus::Right);
}

#[test]
fn arrow_keys_move_cursor_within_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    for ch in "hello".chars() {
        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()),
        );
    }
    assert_eq!(app.input(), "hello");
    assert_eq!(app.cursor(), 5);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Left, KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Left, KeyModifiers::empty()),
    );
    assert_eq!(app.cursor(), 3);

    // Insert a char in the middle.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('X'), KeyModifiers::empty()),
    );
    assert_eq!(app.input(), "helXlo");
    assert_eq!(app.cursor(), 4);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Home, KeyModifiers::empty()),
    );
    assert_eq!(app.cursor(), 0);
    press_key(&mut app, KeyEvent::new(KeyCode::End, KeyModifiers::empty()));
    assert_eq!(app.cursor(), app.input().chars().count());
}

#[test]
fn ctrl_w_deletes_word_left() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("scan ./path/to/foo");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input(), "scan ./path/to/");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input(), "scan ./path/");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input(), "");
    assert_eq!(app.cursor(), 0);
}

#[test]
fn ctrl_a_e_b_f_navigate_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("abcd");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.cursor(), 0);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.cursor(), 1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.cursor(), 4);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.cursor(), 3);
}

#[test]
fn up_arrow_recalls_command_history() {
    let mut app = ShellApp::new(V2Config::default(), None);
    submit_shell_line(&mut app, "/findings");
    submit_shell_line(&mut app, "/modules");
    assert!(app.input().is_empty());

    press_key(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.input(), "/modules");
    press_key(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.input(), "/findings");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
    );
    assert_eq!(app.input(), "/modules");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
    );
    assert_eq!(app.input(), "");
}

#[test]
fn page_keys_scroll_view_offset() {
    // Help has its own dedicated scroll field — PageDown/PageUp must
    // advance/retract it so `viewport_lines(..., app.router.help().scroll())` actually
    // shows the next page. Other views with their own scroll fields
    // (Tools, History, KnowledgeBase, Catalog when expanded) work the
    // same way; views without dedicated fields fall back to the router-owned
    // default scroll state.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.help().scroll(), 10);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.help().scroll(), 20);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty()),
    );
    assert_eq!(app.router.help().scroll(), 10);

    // Views without a dedicated scroll field still use the default scroll route.
    app.set_shell_view(ShellView::Tune);
    app.router.default_scroll_mut().reset();
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.default_scroll().offset(), 10);
}

#[test]
fn changing_view_resets_default_scroll() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);
    app.router.default_scroll_mut().set(25);
    app.sync_view_change();
    // First sync after construction: no synced router view exists, so scroll resets.
    assert_eq!(app.router.default_scroll().offset(), 0);
    // Move scroll, switch view, sync again — scroll resets again.
    app.router.default_scroll_mut().set(12);
    app.set_shell_view(ShellView::Tools);
    app.sync_view_change();
    assert_eq!(app.router.default_scroll().offset(), 0);
}

#[test]
fn completion_preview_shows_only_when_cursor_at_end() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("/he");
    // Cursor at end → preview returns the tail "lp".
    let preview = app.completion_preview();
    assert_eq!(preview.as_deref(), Some("lp"));

    // Move cursor mid-line → preview suppressed (would render in the wrong place).
    app.set_cursor(1);
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
    app.set_shell_view(ShellView::Help);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.default_scroll().offset(), 2);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.default_scroll().offset(), 1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.default_scroll().offset(), u16::MAX);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.default_scroll().offset(), 0);
}

#[test]
fn tick_advances_spinner_only_when_running() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let initial_phase = app.ui().spinner_phase();
    // Idle: tick() returns false and does not advance the spinner.
    let changed = app.tick();
    assert!(!changed);
    assert_eq!(app.ui().spinner_phase(), initial_phase);
    // Mark a scan as running and tick — the spinner advances and tick reports change.
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    // Force the spinner to advance even though no real time has passed.
    app.ui_mut()
        .set_last_spinner_advance_for_test(Instant::now() - Duration::from_millis(200));
    let changed = app.tick();
    assert!(changed);
    assert_eq!(app.ui().spinner_phase(), initial_phase.wrapping_add(1));
}

#[test]
fn pgdown_pgup_paginate_findings_cursor() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    *app.findings_mut() = (0..25)
        .map(|i| make_finding(Severity::High, &format!("fp-{i}"), "x"))
        .collect();
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 10);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 20);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 24);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty()),
    );
    assert_eq!(app.router.findings().cursor(), 14);
}

#[test]
fn viewport_enter_opens_cursor_finding_from_visible_list() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    *app.findings_mut() = vec![
        make_finding(Severity::High, "fp-0000", "first"),
        make_finding(Severity::High, "fp-0001", "second"),
    ];
    app.router.findings_mut().set_cursor(1);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    // Enter selects the cursored finding; the Workbench DETAILS pane shows it.
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| finding.title.as_str()),
        Some("second")
    );
}

#[test]
fn viewport_enter_opens_projected_cursor_finding_after_duplicate_group() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    *app.findings_mut() = vec![
        make_projected_duplicate(Severity::Medium, "fp-duplicate-medium", "duplicate medium"),
        make_projected_duplicate(Severity::High, "fp-duplicate-high", "duplicate high"),
        make_finding(Severity::Low, "fp-distinct-low", "distinct low"),
    ];
    app.router.findings_mut().set_cursor(1);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| finding.title.as_str()),
        Some("distinct low")
    );
}

#[test]
fn workbench_esc_returns_focus_to_findings_before_leaving() {
    let mut app = app_with_findings(2);
    app.push_nav_history(ShellView::Catalog);
    app.router.workbench_mut().set_focus(WorkbenchPane::Details);

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Catalog);
}

#[test]
fn workbench_tab_preserves_each_pane_scroll_position() {
    let mut app = app_with_findings(2);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router.workbench_mut().set_focus(WorkbenchPane::Details);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()),
    );

    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
    assert_eq!(app.router.workbench().scroll().details, 1);
    assert_eq!(app.router.workbench().scroll().center, 1);
}

#[test]
fn keybind_advertised_workbench_hotkeys_drive_state_transitions() {
    let app = app_with_findings(25);
    let advertised = app.view_keybindings();
    assert!(advertised.iter().any(|binding| binding.hint == "Tab"));
    assert!(advertised.iter().any(|binding| binding.hint == "Shift+Tab"));
    assert!(advertised
        .iter()
        .any(|binding| binding.hint.contains("j/k")));
    assert!(advertised.iter().any(|binding| binding.hint == "d"));
    assert!(advertised.iter().any(|binding| binding.hint == "←/→"));
    assert!(advertised.iter().any(|binding| binding.hint == "[/]"));
    assert!(advertised.iter().any(|binding| binding.hint == "z"));
    assert!(advertised.iter().any(|binding| binding.hint == "1..4"));
    assert!(advertised.iter().any(|binding| binding.hint == "n/N"));
    assert!(advertised.iter().any(|binding| binding.hint == "v"));
    assert!(advertised.iter().any(|binding| binding.hint == "c"));
    assert!(advertised.iter().any(|binding| binding.hint == "D"));
    assert!(advertised.iter().any(|binding| binding.hint == "Enter"));

    for binding in advertised {
        let mut app = app_with_findings(25);
        if binding.action != ViewHotkeyAction::Back {
            app.set_input_mode(crate::InputMode::Navigate);
        }
        match binding.action {
            ViewHotkeyAction::WorkbenchCyclePane => {
                // app_with_findings starts on the FINDINGS pane; Tab advances
                // to DETAILS (Source → Center → Findings → Details → Source).
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
            }
            ViewHotkeyAction::WorkbenchCyclePanePrev => {
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);
            }
            ViewHotkeyAction::WorkbenchScrollNext => {
                app.router.findings_mut().set_cursor(0);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.findings().cursor(), 1);
            }
            ViewHotkeyAction::WorkbenchScrollPrev => {
                app.router.findings_mut().set_cursor(1);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.findings().cursor(), 0);
            }
            ViewHotkeyAction::WorkbenchScrollFirst => {
                app.router.findings_mut().set_cursor(7);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.findings().cursor(), 0);
            }
            ViewHotkeyAction::WorkbenchScrollLast => {
                app.router.findings_mut().set_cursor(7);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.findings().cursor(), 24);
            }
            ViewHotkeyAction::WorkbenchToggleCenter => {
                app.router.workbench_mut().set_focus(WorkbenchPane::Center);
                assert_eq!(
                    app.router.workbench().center_mode(),
                    WorkbenchCenterMode::Code
                );
                app.router.workbench_mut().scroll_mut().center = 7;
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);
                assert_eq!(
                    app.router.workbench().center_mode(),
                    WorkbenchCenterMode::Dfd
                );
                assert_eq!(app.router.workbench().scroll().center, 0);
            }
            ViewHotkeyAction::WorkbenchCenterNext => {
                app.router.workbench_mut().scroll_mut().center = 7;
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);
                assert_eq!(
                    app.router.workbench().center_mode(),
                    WorkbenchCenterMode::Dfd
                );
                assert_eq!(app.router.workbench().scroll().center, 0);
            }
            ViewHotkeyAction::WorkbenchCenterPrev => {
                app.router.workbench_mut().scroll_mut().center = 7;
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);
                assert_eq!(
                    app.router.workbench().center_mode(),
                    WorkbenchCenterMode::Risk
                );
                assert_eq!(app.router.workbench().scroll().center, 0);
            }
            ViewHotkeyAction::WorkbenchZoomCenter => {
                use crate::scene3d::VizPage;

                app.router.workbench_mut().set_focus(WorkbenchPane::Center);
                app.router
                    .workbench_mut()
                    .set_center_mode(WorkbenchCenterMode::Dfd);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view(), ShellView::Scene);
                assert_eq!(app.router.scene().page(), VizPage::Dfd);
            }
            ViewHotkeyAction::WorkbenchOpen => {
                app.router.findings_mut().set_cursor(2);
                app.router
                    .workbench_mut()
                    .set_center_mode(WorkbenchCenterMode::Dfd);
                let expected = app.findings()[2].fingerprint.clone();
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view(), ShellView::Workbench);
                assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
                assert_eq!(
                    app.router.workbench().center_mode(),
                    WorkbenchCenterMode::Code
                );
                assert_eq!(
                    app.selected_finding()
                        .as_ref()
                        .map(|finding| finding.fingerprint.as_str()),
                    Some(expected.as_str())
                );
            }
            ViewHotkeyAction::WorkbenchPage(page) => {
                app.router.workbench_mut().scroll_mut().center = 7;
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().page(), Some(page));
                assert_eq!(app.router.workbench().scroll().center, 0);
                assert_eq!(
                    app.router.workbench().focus(),
                    if page == WorkbenchPage::Review {
                        WorkbenchPane::Findings
                    } else {
                        WorkbenchPane::Center
                    }
                );
            }
            ViewHotkeyAction::WorkbenchPageNext => {
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Ship));
            }
            ViewHotkeyAction::WorkbenchPagePrev => {
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Coverage));
            }
            ViewHotkeyAction::WorkbenchValidate => {
                app.findings_mut().clear();
                *app.selected_finding_mut() = None;
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert!(app.log_lines().iter().any(|line| {
                    line.prefix == "verify" && line.body.contains("no finding selected")
                }));
            }
            ViewHotkeyAction::WorkbenchOrderChain => {
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert!(!app.tool_is_running());
            }
            ViewHotkeyAction::WorkbenchCluster => {
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Coverage));
                assert!(app.log_lines().iter().any(|line| {
                    line.prefix == "cluster" && line.body.contains("distinct sinks")
                }));
            }
            ViewHotkeyAction::OpenNextPhase => {
                let target = tempfile::tempdir().unwrap();
                app.set_target(Some(target.path().to_path_buf()));
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert!(matches!(app.shell_view(), ShellView::PlanningPicker));
            }
            ViewHotkeyAction::Back => {
                let mut app = app_with_findings(25);
                app.push_nav_history(ShellView::Catalog);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view(), ShellView::Catalog);
            }
            other => panic!("unexpected workbench hotkey action: {other:?}"),
        }
    }
}

#[test]
fn non_review_workbench_pages_keep_tab_focus_on_visible_body() {
    let mut app = app_with_findings(2);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Coverage));
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);

    press_key(&mut app, key_event_for_trigger(HotkeyTrigger::Tab));
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);

    app.router.workbench_mut().set_focus(WorkbenchPane::Details);
    press_key(&mut app, key_event_for_trigger(HotkeyTrigger::BackTab));
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Center);
}

#[test]
fn prompt_show_local_reducer_returns_show_effect_without_reading_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "focus on auth bypass").unwrap();

    let update = app.reduce_submitted_line("show triage");
    let show = prompt_override_show_effect(&update.effects).expect("prompt show effect");

    assert!(update.handled);
    assert_eq!(show.path, path);
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| { line.body.contains("override ") && line.body.contains("bytes") }));

    EffectRuntime::execute(&mut app, update.effects);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body == "focus on auth bypass"));
}

#[test]
fn prompt_diff_local_reducer_returns_diff_effect_without_metadata_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "focus on auth bypass").unwrap();

    let update = app.reduce_submitted_line("diff triage");
    let diff = prompt_override_diff_effect(&update.effects).expect("prompt diff effect");

    assert!(update.handled);
    assert_eq!(diff.path, path);
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| { line.body.contains("diff candidate: git diff --") }));

    EffectRuntime::execute(&mut app, update.effects);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("diff candidate: git diff --")));
}

#[test]
fn prompt_list_local_reducer_returns_list_effect_without_reading_dir() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);
    let dir = temp.path().join(".kuzushi/prompts/sast");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("triage.md"), "focus on auth bypass").unwrap();

    let update = app.reduce_submitted_line("list");
    let list = prompt_override_list_effect(&update.effects).expect("prompt list effect");

    assert!(update.handled);
    assert_eq!(list.dir, dir);
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("overrides in")));

    EffectRuntime::execute(&mut app, update.effects);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("triage")));
}

#[test]
fn prompt_edit_local_reducer_returns_edit_effect_without_touching_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);

    let update = app.reduce_submitted_line("edit triage");
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    let edit = prompt_override_edit_effect(&update.effects).expect("prompt edit effect");

    assert!(update.handled);
    assert_eq!(edit.path, path);
    assert!(!path.exists());

    EffectRuntime::execute(&mut app, update.effects);
    assert!(path.exists());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("edit override at")));
}

#[test]
fn prompt_set_local_reducer_returns_write_effect_without_touching_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);

    let update = app.reduce_submitted_line("set triage \"focus on auth bypass\"");
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    let write = prompt_override_write_effect(&update.effects).expect("prompt write effect");

    assert!(update.handled);
    assert_eq!(write.path, path);
    assert_eq!(write.value, "focus on auth bypass");
    assert!(!path.exists());

    EffectRuntime::execute(&mut app, update.effects);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "focus on auth bypass"
    );
}

#[test]
fn prompt_reset_local_reducer_returns_reset_effect_without_touching_disk() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "focus on auth bypass").unwrap();

    let update = app.reduce_submitted_line("reset triage");
    let reset = prompt_override_reset_effect(&update.effects).expect("prompt reset effect");

    assert!(update.handled);
    assert_eq!(reset.path, path);
    assert!(path.exists());

    EffectRuntime::execute(&mut app, update.effects);
    assert!(!path.exists());
}

#[test]
fn prompt_set_writes_override_file_and_reset_removes_it() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::PromptsEditor);

    submit_shell_line(&mut app, "set triage \"focus on auth bypass\"");
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    assert!(path.exists());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "focus on auth bypass"
    );

    submit_shell_line(&mut app, "reset triage");
    assert!(!path.exists());
}

#[test]
fn bare_verbs_only_intercepted_in_prompts_editor_view() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    // NOT in prompts editor — should fall through to normal parser, which treats
    // unknown bare verbs as Unknown (not a prompt write).
    app.set_shell_view(ShellView::Catalog);
    submit_shell_line(&mut app, "set triage \"abc\"");
    let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
    assert!(!path.exists());
}

#[test]
fn ctrl_o_toggles_story_overlay_back_to_origin() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.shell_view(), ShellView::Story);
    assert!(app
        .router
        .navigation()
        .contains_history(&ShellView::Workbench));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(!app
        .router
        .navigation()
        .contains_history(&ShellView::Workbench));
    app.sync_view_change();
    assert!(!app.router.navigation().contains_history(&ShellView::Story));
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
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    run_command(&mut app, ShellCommand::Pause);
    assert!(cancel.is_paused());
    assert!(app.is_scan_paused());
    assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("paused"));
}

#[test]
fn resume_command_resumes_paused_scan() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    cancel.pause();
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "paused".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    run_command(&mut app, ShellCommand::Resume(None));
    assert!(!cancel.is_paused());
    assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("running"));
}

#[test]
fn module_run_p_and_r_keys_pause_resume() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_shell_view(ShellView::ModuleRun);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()),
    );
    assert!(cancel.is_paused());
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()),
    );
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
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view(), ShellView::ActorDetail);
                assert_eq!(app.router.actor_detail().index(), index);
            }
            ViewHotkeyAction::PauseScan => {
                let (mut app, cancel) = app_with_module_run_scan(false);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert!(cancel.is_paused());
                assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("paused"));
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
                press_key(&mut app, key_event_for_trigger(binding.trigger));
            }
            ViewHotkeyAction::Back => {
                let (mut app, _) = app_with_module_run_scan(false);
                app.push_nav_history(ShellView::Catalog);
                press_key(&mut app, key_event_for_trigger(binding.trigger));
                assert_eq!(app.shell_view(), ShellView::Catalog);
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
        press_key(&mut app, key_event_for_trigger(binding.trigger));
        assert!(!cancel.is_paused());
        assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("running"));
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
        app.set_shell_view(view.clone());
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
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Catalog);
}

#[test]
fn esc_clears_draft_instead_of_going_back_when_typing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.set_input("scan");
    app.set_cursor(app.input().chars().count());

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Tools, "view must not change");
    assert!(app.input().is_empty(), "draft should be cleared");
    assert_eq!(app.last_cleared_input(), Some("scan"));
}

#[test]
fn esc_goes_back_with_stashed_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.set_last_cleared_input(Some("scan".to_string()));

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Catalog);
    assert!(app.input().is_empty(), "stashed draft should stay explicit");
    assert_eq!(app.last_cleared_input(), Some("scan"));
}

#[test]
fn ctrl_underscore_restores_stashed_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.set_last_cleared_input(Some("scan".to_string()));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('_'), KeyModifiers::CONTROL),
    );

    assert_eq!(app.shell_view(), ShellView::Tools, "view must not change");
    assert_eq!(app.input(), "scan", "stashed draft should be restored");
    assert!(app.last_cleared_input().is_none());
}

#[test]
fn esc_back_stays_advertised_after_a_draft_clear_and_view_change() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.set_input("scan");

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.last_cleared_input(), Some("scan"));
    assert!(app
        .view_keybindings()
        .iter()
        .any(|binding| binding.action == ViewHotkeyAction::Back));

    run_command(&mut app, ShellCommand::Help(None));

    assert!(app.last_cleared_input().is_none());
    assert!(app
        .view_keybindings()
        .iter()
        .any(|binding| binding.action == ViewHotkeyAction::Back));

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Catalog);
    assert!(app.input().is_empty(), "stale draft must not be restored");
}

#[test]
fn submitting_a_command_clears_stashed_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.set_last_cleared_input(Some("scan".to_string()));
    app.set_input("help");

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Help);
    assert!(app.last_cleared_input().is_none());
    assert!(app.input().is_empty());
}

#[test]
fn activity_view_offers_back_binding() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    assert!(
        app.view_keybindings()
            .iter()
            .any(|binding| binding.action == ViewHotkeyAction::Back),
        "Activity should advertise Esc back; cancellation is armed separately"
    );
}

#[test]
fn taskless_activity_task_keys_log_why_they_do_not_focus() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    app.set_activity(Some(ActivitySession::new("run-1")));
    app.set_input_mode(crate::InputMode::Navigate);

    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert!(
        app.input().is_empty(),
        "task hotkeys must not leak into prompt"
    );
    let explanations = app
        .log_lines()
        .iter()
        .filter(|line| {
            line.prefix == "activity"
                && line
                    .body
                    .contains("no task rows to focus; output is already full width")
        })
        .count();
    assert_eq!(explanations, 2);
}

#[test]
fn picker_views_are_not_recorded_in_nav_history() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ModelPicker);
    app.sync_view_change();
    app.set_shell_view(ShellView::Catalog);
    app.sync_view_change();

    assert!(
        !app.router
            .navigation()
            .contains_history(&ShellView::ModelPicker),
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
    app.set_target(Some(target.clone()));
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
    update_and_execute_effects(&mut app, Msg::Cmd(ShellCommand::ThreatApply));
    let written = load_persistent_threat_model(&target).unwrap();
    assert_eq!(
        written
            .pointer("/trustZones/admin")
            .and_then(|v| v.as_str()),
        Some("isolated")
    );
    assert!(!app.engagement.has_pending_threat_patch());
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
    assert!(!app.engagement.has_pending_threat_patch());
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
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::empty()),
    );
    assert!(!app.engagement.has_pending_plan());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("noted")));
}

#[test]
fn pending_plan_enter_applies_default() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_plan(PlanProposal {
        goal: "g".to_string(),
        summary: "s".to_string(),
        changes: vec![PlanChange::Note {
            text: "accepted by enter".to_string(),
        }],
        unsupported: vec![],
    });
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert!(!app.engagement.has_pending_plan());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("accepted by enter")));
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
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()),
    );
    assert!(!app.engagement.has_pending_plan());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "plan" && line.body.contains("discarded")));
}

#[test]
fn plan_apply_without_pending_plan_explains_no_action() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::PlanApply);

    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "plan" && line.body.contains("nothing to apply")));
}

#[test]
fn plan_discard_without_pending_plan_explains_no_action() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::PlanDiscard);

    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "plan" && line.body.contains("nothing to discard")));
}

#[test]
fn budget_halt_c_continues_a_aborts() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(0.05));
    app.record_cost(0.10);
    assert!(app.is_budget_halted());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()),
    );
    assert!(!app.is_budget_halted(), "c should clear the halt");

    app.session_mut().set_session_cost_usd_for_test(0.30);
    app.session_mut().set_session_budget_usd(Some(0.20));
    app.record_cost(0.0);
    // Force re-trigger by lowering cap and recording zero (helper rechecks).
    app.advisory_mut().budget_halt = Some(BudgetHalt {
        limit_usd: 0.20,
        spent_usd: 0.30,
    });
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()),
    );
    assert!(!app.is_budget_halted(), "a should clear the halt");
}

#[test]
fn budget_continue_key_returns_effect_without_mutating_cap_inline() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(0.05));
    app.record_cost(0.10);
    assert!(app.is_budget_halted());

    let before_budget = app.session().session_budget_usd();
    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert!(matches!(
        result.effects.as_slice(),
        [ShellEffect::ContinuePastBudget]
    ));
    assert_eq!(app.session().session_budget_usd(), before_budget);
    assert!(app.is_budget_halted());

    EffectRuntime::execute(&mut app, result.effects);
    assert!(!app.is_budget_halted());
    assert_ne!(app.session().session_budget_usd(), before_budget);
}

#[test]
fn budget_abort_key_returns_effect_without_cancelling_inline() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_running_tool_for_test("semgrep:scan");
    app.set_tool_cancel_for_test(cancel.clone());
    app.advisory_mut().budget_halt = Some(BudgetHalt {
        limit_usd: 0.20,
        spent_usd: 0.30,
    });

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('a'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert!(matches!(
        result.effects.as_slice(),
        [ShellEffect::AbortForBudget]
    ));
    assert!(app.is_budget_halted());
    assert!(!cancel.is_cancelled());
    assert!(!app.tool_abort_requested());

    EffectRuntime::execute(&mut app, result.effects);
    assert!(!app.is_budget_halted());
    assert!(cancel.is_cancelled());
    assert!(app.tool_abort_requested());
}

#[test]
fn ctrl_c_during_active_scan_requests_abort_without_arming_exit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-x".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(!app.should_quit());
    assert!(!app.ctrl_c_armed());
    assert!(app.scan().is_some_and(|scan| scan.abort_requested));
}

#[test]
fn ctrl_c_during_active_scan_marks_run_job_cancel_requested() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "scan");
    let cancel = ticket.cancel.clone();
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-x".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(cancel.is_cancelled());
    assert!(app.jobs().cancel_requested(JobKind::Run));
    assert!(app.scan().is_some_and(|scan| scan.abort_requested));
}

#[test]
fn second_ctrl_c_after_scan_abort_request_keeps_waiting() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-x".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_scan_cancel_for_test(cancel.clone());
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(!app.should_quit());
    assert!(cancel.is_cancelled());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("abort already requested")));
}

#[test]
fn ctrl_c_during_agent_chat_requests_abort_without_claiming_kill() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Agent, "agent");
    let cancel = ticket.cancel.clone();
    app.set_shell_view(ShellView::AgentChat);
    app.set_agent_cancel(Some(cancel.clone()));
    app.set_agent_chat(Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        screen_context_scope: None,
        failure_context: None,
        pending_failure_context: None,
    }));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(!app.should_quit());
    assert!(!app.ctrl_c_armed());
    assert!(app.agent_chat().is_some_and(|agent| agent.abort_requested));
    assert!(cancel.is_cancelled());
    assert!(app.jobs().cancel_requested(JobKind::Agent));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "agent"
            && line.body.contains("abort requested")
            && line.body.contains("not confirmed")
    }));
}

#[test]
fn agent_response_after_abort_request_is_ignored() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_agent_chat(Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: true,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        screen_context_scope: None,
        failure_context: None,
        pending_failure_context: None,
    }));

    app.apply_agent_event(AgentEvent::Answered {
        text: "late answer".to_string(),
        audit: test_agent_audit(),
    });

    let agent = app.agent_chat().unwrap();
    assert!(!agent.running);
    assert!(!agent.abort_requested);
    assert!(agent.answer.is_none());
    assert!(agent
        .error
        .as_ref()
        .is_some_and(|error| error.contains("ignored")));
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body == "late answer"));
}

#[test]
fn agent_answer_event_records_llm_audit_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_agent_chat(Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: Some("agent-answer".to_string()),
        started_secs: 0,
        screen_context_scope: None,
        failure_context: None,
        pending_failure_context: None,
    }));

    let effects = app.apply_agent_event(AgentEvent::Answered {
        text: "inspect report.md".to_string(),
        audit: test_agent_audit(),
    });

    assert_eq!(app.session().last_tool_cost_usd(), Some(0.012));
    assert!((app.session().session_cost_usd() - 0.012).abs() < f64::EPSILON);
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::RecordAgentRun(_)]
    ));
    assert!(!kuzushi_core::run_dir(tmp.path(), "agent-answer")
        .join("events.jsonl")
        .exists());
    EffectRuntime::execute(&mut app, effects);

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
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_agent_chat(Some(AgentChatView {
        question: "what changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: Some("agent-failed".to_string()),
        started_secs: 0,
        screen_context_scope: None,
        failure_context: None,
        pending_failure_context: None,
    }));

    let effects = app.apply_agent_event(AgentEvent::Failed {
        error: "bridge denied the model request".to_string(),
        audit: test_agent_audit(),
    });

    assert_eq!(app.session().last_tool_cost_usd(), Some(0.012));
    assert!((app.session().session_cost_usd() - 0.012).abs() < f64::EPSILON);
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::RecordAgentRun(_)]
    ));
    assert!(!kuzushi_core::run_dir(tmp.path(), "agent-failed")
        .join("events.jsonl")
        .exists());
    EffectRuntime::execute(&mut app, effects);

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
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("scan-failed".to_string()),
        target: tmp.path().to_path_buf(),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let effects = app.apply_scan_failed("semgrep binary missing".to_string());

    assert!(!kuzushi_core::run_dir(tmp.path(), "scan-failed")
        .join("failures.json")
        .exists());
    EffectRuntime::execute(&mut app, effects);
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
    let plan_ticket = app.jobs_mut().start(JobKind::Plan, "planner");
    let plan_cancel = plan_ticket.cancel.clone();
    let threat_ticket = app.jobs_mut().start(JobKind::Threat, "threat model");
    let threat_cancel = threat_ticket.cancel.clone();
    app.set_planner_running(true);
    app.set_plan_cancel(Some(plan_cancel.clone()));
    app.set_threat_worker_running(true);
    app.set_threat_cancel(Some(threat_cancel.clone()));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(app.plan_abort_requested());
    assert!(app.threat_abort_requested());
    assert!(plan_cancel.is_cancelled());
    assert!(app.jobs().cancel_requested(JobKind::Plan));
    assert!(threat_cancel.is_cancelled());
    assert!(app.jobs().cancel_requested(JobKind::Threat));
    assert!(!app.should_quit());
    assert!(!app.ctrl_c_armed());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "plan"
            && line.body.contains("abort requested")
            && line.body.contains("not confirmed")
    }));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "threats"
            && line.body.contains("abort requested")
            && line.body.contains("not confirmed")
    }));
}

#[test]
fn ctrl_c_during_background_tool_requests_honest_abort_without_exiting() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_running_tool_for_test("context:build");
    app.set_tool_cancel_for_test(cancel.clone());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(app.tool_abort_requested());
    assert!(cancel.is_cancelled());
    assert!(!app.ctrl_c_armed());
    assert!(!app.should_quit());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "tool"
            && line.body.contains("context:build cancel requested")
            && line.body.contains("worker to stop")
    }));
}

#[test]
fn ctrl_c_during_background_tool_marks_run_job_cancel_requested() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "context:build");
    let cancel = ticket.cancel.clone();
    app.set_running_tool_for_test("context:build");
    app.set_tool_cancel_for_test(cancel.clone());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(cancel.is_cancelled());
    assert!(app.jobs().cancel_requested(JobKind::Run));
    assert!(app.tool_abort_requested());
}

#[test]
fn exit_abort_effect_cancels_all_running_job_slots() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let run = app.jobs_mut().start(JobKind::Run, "scan").cancel.clone();
    let agent = app.jobs_mut().start(JobKind::Agent, "agent").cancel.clone();
    let plan = app
        .jobs_mut()
        .start(JobKind::Plan, "planner")
        .cancel
        .clone();
    let threat = app
        .jobs_mut()
        .start(JobKind::Threat, "threat model")
        .cancel
        .clone();

    app.request_exit_abort_effect();

    assert!(run.is_cancelled());
    assert!(agent.is_cancelled());
    assert!(plan.is_cancelled());
    assert!(threat.is_cancelled());
    assert!(app.jobs().cancel_requested(JobKind::Run));
    assert!(app.jobs().cancel_requested(JobKind::Agent));
    assert!(app.jobs().cancel_requested(JobKind::Plan));
    assert!(app.jobs().cancel_requested(JobKind::Threat));
}

#[test]
fn exit_abort_effect_keeps_legacy_token_fallback() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let scan = ScanCancellation::default();
    let tool = ScanCancellation::default();
    let agent = ScanCancellation::default();
    let plan = ScanCancellation::default();
    let threat = ScanCancellation::default();
    app.set_scan_cancel_for_test(scan.clone());
    app.set_tool_cancel_for_test(tool.clone());
    app.set_agent_cancel(Some(agent.clone()));
    app.set_plan_cancel(Some(plan.clone()));
    app.set_threat_cancel(Some(threat.clone()));

    app.request_exit_abort_effect();

    assert!(scan.is_cancelled());
    assert!(tool.is_cancelled());
    assert!(agent.is_cancelled());
    assert!(plan.is_cancelled());
    assert!(threat.is_cancelled());
}

#[test]
fn second_ctrl_c_during_background_tool_keeps_waiting_for_worker() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_running_tool_for_test("triage:run");
    app.set_tool_cancel_for_test(cancel.clone());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(app.tool_abort_requested());
    assert!(cancel.is_cancelled());
    assert!(!app.should_quit());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("abort already requested")));
}

#[test]
fn activity_ctrl_c_cancels_scan_and_background_tool_without_leaving_tui() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let scan_cancel = ScanCancellation::default();
    let tool_cancel = ScanCancellation::default();
    app.set_shell_view(ShellView::Activity);
    app.set_activity(Some(ActivitySession::new("tool-x")));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("scan-run".to_string()),
        target: tmp.path().to_path_buf(),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_scan_cancel_for_test(scan_cancel.clone());
    app.set_running_tool_for_test("triage:run");
    app.set_tool_cancel_for_test(tool_cancel.clone());

    assert!(!app
        .view_keybindings()
        .iter()
        .any(|binding| binding.hint == "C"));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(app.scan().is_some_and(|scan| scan.abort_requested));
    assert!(scan_cancel.is_cancelled());
    assert!(app.tool_abort_requested());
    assert!(tool_cancel.is_cancelled());
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(!app.should_quit());
    assert!(!app.ctrl_c_armed());
}

#[test]
fn cancel_command_cancels_background_tool_without_exiting() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_running_tool_for_test("triage:run");
    app.set_tool_cancel_for_test(cancel.clone());

    run_command(&mut app, ShellCommand::Cancel);

    assert!(app.tool_abort_requested());
    assert!(cancel.is_cancelled());
    assert!(!app.should_quit());
}

#[test]
fn background_tool_failure_clears_running_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_running_tool_for_test("randori:pasta");
    app.set_tool_abort_requested_for_test(true);

    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "randori:pasta".to_string(),
        error: "randori:pasta could not satisfy structured JSON contract `ThreatModelDocument`"
            .to_string(),
    });

    assert_eq!(app.running_tool_name(), None);
    assert!(!app.tool_abort_requested());
    assert!(app.log_lines().iter().any(|line| {
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
    app.set_activity(Some(ActivitySession::new("run-1")));
    app.set_running_tool_for_test("cpg:build");
    // Seed the row as the start step would, leaving it Active/running.
    app.activity_mut().unwrap().apply_step(
        kuzushi_core::RunTraceStep::new(0, "tool", "cpg:build start")
            .with_module_id("cpg")
            .with_verb("build"),
    );
    assert_eq!(
        app.activity().unwrap().tasks["cpg:build"].state,
        crate::DagTaskState::Active
    );

    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "cpg:build".to_string(),
        error: "joern-parse exited with status Some(1): astgen not found".to_string(),
    });

    let row = &app.activity().unwrap().tasks["cpg:build"];
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
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_active_tool_run_id_for_test("tool-failed");
    app.set_running_tool_for_test("semgrep:scan");

    let effects = app.apply_tool_event(ToolEvent::Failed {
        tool_name: "semgrep:scan".to_string(),
        error: "semgrep binary missing".to_string(),
    });

    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::RecordToolRun(_)]
    ));
    assert!(!kuzushi_core::run_dir(tmp.path(), "tool-failed")
        .join("failures.json")
        .exists());
    assert!(!app.log_lines().iter().any(|line| line.prefix == "result"));
    EffectRuntime::execute(&mut app, effects);

    let result_log = app
        .log_lines()
        .iter()
        .find(|line| line.prefix == "result")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(result_log.contains("\"status\": \"failed\""));
    assert!(result_log.contains("\"fallback_context\""));
    assert!(result_log.contains("\"failedStage\": \"semgrep:scan\""));
    assert!(result_log.contains("semgrep binary missing"));
    assert!(app.log_lines().iter().any(|line| {
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
        .agent_chat()
        .and_then(|agent| agent.failure_context.as_ref())
        .is_some_and(|context| context.failed_stage == "semgrep:scan"));
    assert!(app
        .agent_chat()
        .and_then(|agent| agent.pending_failure_context.as_ref())
        .is_some_and(|context| context.failed_stage == "semgrep:scan"));
}

#[test]
fn background_tool_partial_result_logs_fallback_context_in_result() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_active_tool_run_id_for_test("tool-partial");
    app.set_running_tool_for_test("codeql:scan");

    let effects = app.apply_tool_event(ToolEvent::Finished {
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

    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::RecordToolRun(_)]
    ));
    assert!(!kuzushi_core::run_dir(tmp.path(), "tool-partial")
        .join("failures.json")
        .exists());
    assert!(!app.log_lines().iter().any(|line| line.prefix == "result"));
    EffectRuntime::execute(&mut app, effects);

    let result_log = app
        .log_lines()
        .iter()
        .rev()
        .find(|line| line.prefix == "result")
        .map(|line| line.body.clone())
        .unwrap_or_default();
    assert!(result_log.contains("fallback_context"));
    assert!(result_log.contains("\"failedStage\": \"codeql:scan\""));
    assert!(app
        .agent_chat()
        .and_then(|agent| agent.pending_failure_context.as_ref())
        .is_some_and(|context| context.failed_stage == "codeql:scan"));
}

#[test]
fn failure_handoff_command_opens_dedicated_view() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::FailureHandoff);

    assert_eq!(app.shell_view(), ShellView::FailureHandoff);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "handoff" && line.body.contains("no failure handoff")));
}

#[test]
fn recommend_command_opens_artifact_backed_view() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::Recommend);

    assert_eq!(app.shell_view(), ShellView::Recommend);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "recommend" && line.body.contains("choose a target")));
}

#[test]
fn recommend_enter_runs_selected_component_scoped_scan() {
    let temp = tempfile::tempdir().unwrap();
    let component_root = temp.path().join("web/app");
    fs::create_dir_all(&component_root).unwrap();
    fs::write(
        component_root.join("config.env"),
        [
            "OPENAI_API_KEY=",
            "sk",
            "-proj-",
            "abcdefghijklmnopqrstuvwxyzABCDEFGH",
        ]
        .concat(),
    )
    .unwrap();
    write_component_recommendation_artifact(
        temp.path(),
        serde_json::json!({
            "scopeId": "package-web-app",
            "relPath": "web/app",
            "class": "web-app",
            "tier": "high",
            "riskScore": 91,
            "reasons": ["web-app component at web/app"],
            "nextInput": {
                "target": temp.path().display().to_string(),
                "paths": ["web/app"],
                "taskMode": "manual",
                "tasks": ["secret-scan"]
            }
        }),
    );
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.session_mut().set_trusted_workflow_auto_accept(true);
    app.set_shell_view(ShellView::Recommend);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    drain_chain_with_auto_reuse(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "component" && line.body.contains("web/app")));
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].file_path.starts_with("web/app/"));
}

#[test]
fn recommend_promote_returns_activation_effect_before_switching_target() {
    let temp = tempfile::tempdir().unwrap();
    let component_root = temp.path().join("web/app");
    fs::create_dir_all(&component_root).unwrap();
    write_component_recommendation_artifact(
        temp.path(),
        serde_json::json!({
            "scopeId": "package-web-app",
            "relPath": "web/app",
            "class": "web-app",
            "tier": "high",
            "riskScore": 91,
            "reasons": ["web-app component at web/app"],
            "nextInput": {
                "target": temp.path().display().to_string(),
                "paths": ["web/app"],
                "taskMode": "manual",
                "tasks": ["secret-scan"]
            }
        }),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_shell_view(ShellView::Recommend);

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('p'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    let activation = target_activation_effect(&result.effects).expect("target activation effect");
    assert_eq!(activation.path, component_root);
    assert!(matches!(activation.source, TargetActivationSource::Command));
    assert_eq!(app.target(), Some(temp.path()));

    EffectRuntime::execute(&mut app, result.effects);

    assert_eq!(
        app.target().and_then(|path| fs::canonicalize(path).ok()),
        fs::canonicalize(temp.path().join("web/app")).ok()
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "component" && line.body.contains("promoted web/app")));
}

#[test]
fn recommend_promote_rejects_paths_outside_active_target() {
    let temp = tempfile::tempdir().unwrap();
    write_component_recommendation_artifact(
        temp.path(),
        serde_json::json!({
            "scopeId": "escape",
            "relPath": "../outside",
            "class": "web-app",
            "tier": "high",
            "riskScore": 91,
            "reasons": ["external path"]
        }),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_shell_view(ShellView::Recommend);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()),
    );

    assert_eq!(app.target(), Some(temp.path()));
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "component" && line.body.contains("target-relative component path")
    }));
}

fn write_component_recommendation_artifact(root: &std::path::Path, component: serde_json::Value) {
    let run_dir = crate::ui_view_models::ui_run_dir(Some(root), "run-components");
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(
        crate::ui_view_models::ui_latest_run_path(Some(root)),
        "run-components\n",
    )
    .unwrap();
    fs::write(
        run_dir.join("recommendations.json"),
        serde_json::json!({
            "status": "completed",
            "data": {
                "components": [component],
                "recommendations": []
            }
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn actor_detail_filter_cycle_and_reset() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.actor_detail_mut().open(1);
    app.set_shell_view(ShellView::ActorDetail);

    assert_eq!(app.router.actor_detail().filter(), ActorDetailFilter::All);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.actor_detail().filter(),
        ActorDetailFilter::Findings
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.actor_detail().filter(),
        ActorDetailFilter::Errors
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.actor_detail().filter(), ActorDetailFilter::Tools);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('0'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.actor_detail().filter(), ActorDetailFilter::All);
}

#[test]
fn prompts_editor_cursor_and_action_shortcuts() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::PromptsEditor);

    assert_eq!(app.current_prompt_verb_name(), Some("scan"));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.current_prompt_verb_name(), Some("triage"));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
    );
    assert_eq!(app.current_prompt_verb_name(), Some("verify"));
    let log_before = app.log_len();
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::empty()),
    );
    assert!(app.log_len() > log_before);
}

#[test]
fn tune_view_cursor_and_activate() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tune);

    assert_eq!(app.router.tune().cursor(), 0);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
    );
    assert_eq!(app.router.tune().cursor(), 1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.tune().cursor(), 2);
    press_key(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    assert_eq!(app.current_tune_action(), Some(TuneAction::EditHouseRules));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert_eq!(app.input(), "set \"\"");
    assert_eq!(app.cursor(), app.input().chars().count() - 1);
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
    let visible = super::settings::visible_model_choice_indexes(app.config().model.as_deref());
    app.router
        .model_catalog_mut()
        .set_selected_index(visible[0]);
    for _ in 0..(visible.len() * 2 + 1) {
        app.move_model_selection(1);
        let selected_index = app.router.model_catalog().selected_index();
        assert!(
            visible.contains(&selected_index),
            "forward step escaped visible set {visible:?}: {}",
            selected_index
        );
    }
    for _ in 0..(visible.len() * 2 + 1) {
        app.move_model_selection(-1);
        let selected_index = app.router.model_catalog().selected_index();
        assert!(
            visible.contains(&selected_index),
            "back step escaped visible set {visible:?}: {}",
            selected_index
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
    app.advisory_mut().pending_confirm = Some(PendingConfirm {
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
        .engagement
        .confirm_allowlist()
        .contains("sandbox:run https://refund.acme/api"));
    assert!(app.advisory().pending_confirm.is_none());
}

#[test]
fn pending_confirm_enter_is_consumed_without_approval() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm = Some(PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "https://refund.acme/api".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    app.set_input("help");

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert!(app.advisory().pending_confirm.is_some());
    assert_eq!(app.input(), "help", "Enter must not submit behind the gate");
    assert!(app.engagement.confirm_allowlist().is_empty());
}

#[test]
fn pending_confirm_y_dispatches_deferred_run_once() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.advisory_mut().pending_confirm = Some(PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "https://refund.acme/api".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    app.advisory_mut().pending_confirm_launch = Some(RunToolLaunch {
        tool_name: "sandbox:run".to_string(),
        input: serde_json::json!({"target": "https://refund.acme/api"}),
        workspace: workspace.clone(),
        thinking_level: Some("high".to_string()),
    });

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('y'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(app.advisory().pending_confirm.is_none());
    assert!(app.advisory().pending_confirm_launch.is_none());
    let [ShellEffect::DispatchRunTool(launch)] = result.effects.as_slice() else {
        panic!("expected one deferred run launch effect");
    };
    assert_eq!(launch.tool_name, "sandbox:run");
    assert_eq!(launch.workspace.root(), workspace.root());
    assert_eq!(launch.thinking_level.as_deref(), Some("high"));
}

#[test]
fn pending_confirm_esc_denies_once_without_navigation() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Tools);
    app.push_nav_history(ShellView::Catalog);
    app.advisory_mut().pending_confirm = Some(PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "https://refund.acme/api".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    app.advisory_mut().pending_confirm_launch = Some(RunToolLaunch {
        tool_name: "sandbox:run".to_string(),
        input: serde_json::json!({"target": "https://refund.acme/api"}),
        workspace: WorkspaceTarget::new(std::env::current_dir().unwrap()).unwrap(),
        thinking_level: None,
    });

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Tools);
    assert!(app.advisory().pending_confirm.is_none());
    assert!(app.advisory().pending_confirm_launch.is_none());
    assert!(app.engagement.confirm_denylist().is_empty());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("denied once")));
}

#[test]
fn append_trace_step_writes_jsonl_under_target() {
    // The trace writer should land at
    // <target>/.kuzushi/v3/runs/<runId>/trace.jsonl with one JSON
    // object per line.
    let tmp = tempfile::tempdir().unwrap();
    append_trace_step(
        Some(tmp.path()),
        "agent-42",
        "plan",
        "ask demo question",
        Some(400),
        None,
    );
    append_trace_step(
        Some(tmp.path()),
        "agent-42",
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
    assert_eq!(second["n"], 2);
    assert_eq!(second["kind"], "llm");
    assert_eq!(second["cost_usd"], 0.012);
}

#[test]
fn append_trace_step_no_op_when_target_is_none() {
    // Sanity: passing None must not pollute the cwd.  The function
    // returns silently.
    append_trace_step(None, "agent-x", "plan", "no target", None, None);
}

#[test]
fn write_run_summary_writes_canonical_run_metadata_under_target() {
    let tmp = tempfile::tempdir().unwrap();
    write_run_summary(Some(tmp.path()), "r-1", "complete", Some(11), "/tmp/demo");
    let body =
        std::fs::read_to_string(run_dir(tmp.path(), "r-1").join("run.json")).expect("run.json");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["status"], "completed");
    assert_eq!(parsed["findings"], 11);
    assert_eq!(parsed["target"], "/tmp/demo");
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
    let patch = app.engagement.pending_patch().expect("pending patch");
    assert_eq!(patch.alias, "F-0001");
    assert!(patch.rationale.contains("sqlx::query!"));
    assert_eq!(patch.tests.len(), 2);
    assert_eq!(
        patch.guardrail.as_deref(),
        Some("approval.patches = human-required")
    );
    assert_eq!(app.shell_view(), ShellView::Patch);
    assert_eq!(app.router.patch().alias(), "F-0001");
}

#[test]
fn patch_reject_command_discards_pending_patch() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "guard tainted input".to_string(),
        side_effect: None,
        diff: "--- a/x.rs\n+++ b/x.rs\n".to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });

    run_command(&mut app, ShellCommand::Patch(PatchCommand::Reject));

    assert!(app.engagement.pending_patch().is_none());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Ship));
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
                "narrative": "request body reaches template rendering",
                "impactDescription": "remote code execution",
                "preconditions": ["templates are enabled"],
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

    let chain_aliases = app.chain_aliases();
    assert_eq!(chain_aliases.len(), 1);
    assert_eq!(chain_aliases[0].id, "C-0001");
    assert_eq!(chain_aliases[0].severity, ChainSeverity::Critical);
    assert_eq!(chain_aliases[0].title, "Template render chain");

    // Detailed chains (with ordered steps) back the attack-tree visualization.
    let exploit_chains = app.domain().exploit_chains();
    assert_eq!(exploit_chains.len(), 1);
    assert_eq!(exploit_chains[0].title, "Template render chain");
    assert_eq!(exploit_chains[0].severity, ChainSeverity::Critical);
    assert_eq!(
        exploit_chains[0].narrative.as_deref(),
        Some("request body reaches template rendering")
    );
    assert_eq!(
        exploit_chains[0].impact_description.as_deref(),
        Some("remote code execution")
    );
    assert_eq!(
        exploit_chains[0].preconditions,
        vec!["templates are enabled".to_string()]
    );
    assert_eq!(exploit_chains[0].steps.len(), 1);
    assert_eq!(exploit_chains[0].steps[0].role, "template-input");
    assert_eq!(exploit_chains[0].steps[0].file, "app.js");
    assert_eq!(exploit_chains[0].steps[0].line, 3);
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
                    {
                        "message": "source: req.query.id",
                        "filePath": "src/routes.ts",
                        "line": 3,
                        "snippet": "const id = req.query.id"
                    },
                    {"message": "sink: db.query", "filePath": "src/db.ts", "line": 7}
                ]
            }]
        }
    });

    app.cache_tool_snapshot("taint-iris:hunt", &result);

    let flow = app.domain().taint_flow().expect("taint flow snapshot");
    assert_eq!(flow.cwe, "CWE-89");
    assert_eq!(flow.severity, "high");
    assert_eq!(flow.stages.len(), 2);
    assert_eq!(flow.stages[0].file, "src/routes.ts");
    assert_eq!(flow.stages[0].line, 3);
    assert_eq!(
        flow.stages[0].snippet.as_deref(),
        Some("const id = req.query.id")
    );
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
    let effects = app.cache_tool_snapshot("pwn:profile-binary", &profile);
    assert!(matches!(effects.as_slice(), [ShellEffect::RefreshPwnState]));
    assert_eq!(
        app.pwn_view().binary,
        Some(std::path::PathBuf::from("/tmp/chal"))
    );
    assert_eq!(
        app.pwn_view().state_path,
        Some(std::path::PathBuf::from("/tmp/state.json"))
    );
    assert!(app.pwn_view().profile_snapshot.is_some());

    let reverse = serde_json::json!({
        "function": "main",
        "revng": {"ok": true, "output": "void main() {}"},
        "dangerousIo": ["gets"]
    });
    app.cache_tool_snapshot("pwn:reverse", &reverse);
    assert_eq!(app.pwn_view().reverse_snapshots.len(), 1);
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

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
    );
    assert_eq!(app.plan_cursor_clamped(), 2);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()),
    );
    assert!(app.plan_change_skipped(2));
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()),
    );
    assert_eq!(app.plan_cursor_clamped(), 1);
    run_command(&mut app, ShellCommand::PlanDiscard);
    assert!(!app.engagement.has_pending_plan());
    assert_eq!(app.plan_cursor_clamped(), 0);
    assert!((0..app.plan_change_count()).all(|idx| !app.plan_change_skipped(idx)));
}

#[test]
fn activity_command_opens_view_and_creates_session() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);
    assert!(matches!(app.shell_view(), ShellView::Home));
    assert!(app.activity().is_none());

    run_command(&mut app, ShellCommand::Activity);

    assert!(matches!(app.shell_view(), ShellView::Activity));
    assert!(
        app.activity().is_some(),
        "/activity should mint a session if none exists"
    );
}

#[test]
fn manual_activity_without_run_job_renders_idle_panel() {
    let mut app = ShellApp::new(V2Config::default(), None);

    run_command(&mut app, ShellCommand::Activity);

    let crate::ui_view_models::ActivityViewModel::Inactive(empty) =
        crate::ui_view_models::activity_view_model(&app)
    else {
        panic!("manual activity with no live run should render the idle panel");
    };
    assert_eq!(empty.title, "ACTIVITY · idle");
    assert_eq!(empty.glyph_label, "no active run");
}

#[test]
fn activity_view_pause_verbose_reset_keys() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);

    // Space freezes only the Activity feed presentation.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()),
    );
    assert!(app.router.activity().paused);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()),
    );
    assert!(!app.router.activity().paused);

    // Verbose toggle.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('V'), KeyModifiers::empty()),
    );
    assert!(app.router.activity().verbose_subsystems);

    // Reset preserves the session while restoring presentation state.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()),
    );
    assert!(app.activity().is_some());
}

#[test]
fn activity_p_key_pauses_real_scan_work_not_the_feed() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_shell_view(ShellView::Activity);
    app.set_activity(Some(ActivitySession::new("run-live")));
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()),
    );

    assert!(cancel.is_paused());
    assert!(!app.router.activity().paused);
    assert_eq!(app.scan().map(|scan| scan.stage.as_str()), Some("paused"));
}

#[test]
fn reset_during_run_job_preserves_run_identity() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    app.set_running_tool_for_test("triage:run");
    app.set_activity(Some(ActivitySession::new("run-live")));
    app.set_input_mode(crate::InputMode::Navigate);
    let route = app.router.activity_mut();
    route.set_deck_page_by_user(super::view_state::ActivityDeckPage::Dfd);
    route.deck_cursor = 4;
    route.task_cursor = 3;
    route.pane_focus = PaneFocus::Right;

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()),
    );

    let session = app.activity().expect("live run session preserved");
    let route = app.router.activity();
    assert_eq!(session.run_id, "run-live");
    assert_eq!(
        route.deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
    assert_eq!(route.deck_cursor, 0);
    assert_eq!(route.task_cursor, 0);
    assert_eq!(route.pane_focus, PaneFocus::Left);
}

#[test]
fn reset_finished_activity_preserves_completed_run() {
    use kuzushi_core::RunTraceStep;

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    let mut session = ActivitySession::new("run-finished");
    session.apply_step(
        RunTraceStep::new(1, "tool", "triage start")
            .with_module_id("triage")
            .with_verb("run"),
    );
    session.apply_step(
        RunTraceStep::new(2, "done", "triage complete")
            .with_module_id("triage")
            .with_verb("run"),
    );
    app.set_activity(Some(session));
    let route = app.router.activity_mut();
    route.set_deck_page_by_user(super::view_state::ActivityDeckPage::Dfd);
    route.focus_task = Some("triage:run".to_string());
    route.feed_scroll = 8;
    route.task_scroll = 2;
    route.deck_cursor = 4;
    route.task_cursor = 3;
    route.pane_focus = PaneFocus::Right;
    route.feed_auto_tail = true;
    app.set_input_mode(crate::InputMode::Navigate);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()),
    );

    let session = app.activity().expect("finished run session preserved");
    let row = session
        .tasks
        .get("triage:run")
        .expect("completed task row preserved");
    assert_eq!(session.run_id, "run-finished");
    assert_eq!(row.state, DagTaskState::Done);
    assert_eq!(session.events.len(), 2);
    let route = app.router.activity();
    assert_eq!(route.focus_task, None);
    assert_eq!(
        route.deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
    assert_eq!(route.feed_scroll, 0);
    assert_eq!(route.task_scroll, 0);
    assert_eq!(route.deck_cursor, 0);
    assert_eq!(route.task_cursor, 0);
    assert_eq!(route.pane_focus, PaneFocus::Left);
    assert!(!route.deck_page_pinned_by_user);
    assert!(!route.feed_auto_tail);
}

#[test]
fn activity_bracket_keys_cycle_deck_pages_and_arrows_do_not() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    assert!(!app.view_keybindings().iter().any(|binding| {
        binding.trigger == HotkeyTrigger::Char('n') || binding.trigger == HotkeyTrigger::Char('N')
    }));
    assert!(!app
        .view_keybindings()
        .iter()
        .any(|binding| binding.hint.contains('←') || binding.hint.contains('→')));

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Right, KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.activity().deck_page,
        super::view_state::ActivityDeckPage::Findings
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char(']'), KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.activity().deck_page,
        super::view_state::ActivityDeckPage::AttackSurface
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('['), KeyModifiers::empty()),
    );
    assert_eq!(
        app.router.activity().deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
}

#[test]
fn activity_left_right_keys_edit_prompt_when_draft_exists() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    app.set_input("scan ./target");
    app.set_cursor(app.input().chars().count());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Left, KeyModifiers::empty()),
    );

    assert_eq!(
        app.router.activity().deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
    assert_eq!(app.cursor(), "scan ./target".chars().count() - 1);
}

#[test]
fn activity_findings_key_opens_workbench_review() {
    let temp = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('f'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "activity" && line.body.contains("opened findings review") }));
}

#[test]
fn activity_open_key_on_findings_opens_workbench_review() {
    let temp = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router
        .activity_mut()
        .set_deck_page(super::view_state::ActivityDeckPage::Findings);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
}

#[test]
fn activity_open_carries_deck_selection_into_workbench() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![
        make_finding(Severity::High, "fp-high", "high row"),
        make_finding(Severity::Critical, "fp-critical", "critical row"),
        make_finding(Severity::Medium, "fp-medium", "medium row"),
    ];
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    let expected = kuzushi_core::sorted_finding_aliases(app.findings())[1]
        .1
        .fingerprint
        .clone();
    let route = app.router.activity_mut();
    route.set_deck_page(super::view_state::ActivityDeckPage::Findings);
    route.deck_cursor = 1;

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert_eq!(app.router.findings().cursor(), 1);
    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| finding.fingerprint.as_str()),
        Some(expected.as_str())
    );
}

#[test]
fn activity_open_uses_projected_findings_deck_index() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![
        make_projected_duplicate(Severity::Medium, "fp-duplicate-medium", "duplicate medium"),
        make_projected_duplicate(Severity::High, "fp-duplicate-high", "duplicate high"),
        make_finding(Severity::Low, "fp-distinct-low", "distinct low"),
    ];
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    let route = app.router.activity_mut();
    route.set_deck_page(super::view_state::ActivityDeckPage::Findings);
    route.deck_cursor = 1;

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert_eq!(app.router.findings().cursor(), 1);
    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| finding.title.as_str()),
        Some("distinct low")
    );
}

#[test]
fn activity_open_key_on_visualization_returns_to_activity_with_q() {
    use crate::scene3d::VizPage;

    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router
        .activity_mut()
        .set_deck_page(super::view_state::ActivityDeckPage::Dfd);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::empty()),
    );
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.router.scene().page(), VizPage::Dfd);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty()),
    );
    assert_eq!(app.shell_view(), ShellView::Activity);
}

#[test]
fn activity_enter_on_artifact_task_switches_output_deck() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    {
        let session = app.activity_mut().unwrap();
        session.tasks.clear();
        session.tasks.insert(
            "threat-model:build".to_string(),
            DagTaskRow::queued(
                "threat-model:build".to_string(),
                "threat-model".to_string(),
                Vec::new(),
            ),
        );
    }
    let route = app.router.activity_mut();
    route.task_cursor = 0;
    route.task_scroll = 0;

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    let route = app.router.activity();
    assert_eq!(route.focus_task.as_deref(), Some("threat-model:build"));
    assert_eq!(route.deck_page, super::view_state::ActivityDeckPage::Dfd);
    assert_eq!(route.pane_focus, PaneFocus::Right);
}

#[test]
fn activity_enter_targets_the_visible_task_cursor() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    let session = app.activity_mut().unwrap();
    session.tasks.clear();
    session.tasks.insert(
        "a:first".to_string(),
        DagTaskRow::queued("a:first".to_string(), "a".to_string(), Vec::new()),
    );
    session.tasks.insert(
        "b:second".to_string(),
        DagTaskRow::queued("b:second".to_string(), "b".to_string(), Vec::new()),
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    let route = app.router.activity();
    assert_eq!(route.task_cursor, 1);
    assert_eq!(route.focus_task.as_deref(), Some("b:second"));
    assert_eq!(
        route.deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
}

#[test]
fn activity_output_deck_omits_redundant_task_page() {
    use kuzushi_core::RunTraceStep;

    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    let session = app.activity_mut().unwrap();
    session.apply_step(
        RunTraceStep::new(1, "tool", "triage start")
            .with_module_id("triage")
            .with_verb("run"),
    );
    session.apply_step(
        RunTraceStep::new(2, "reasoning", "evidence collect")
            .with_module_id("triage")
            .with_verb("run")
            .with_parent_step(1),
    );
    app.router.activity_mut().focus_task = Some("triage:run".to_string());

    let output = render_plain_app(&app, 120);

    assert!(!output.contains("[task]"), "{output}");
    assert!(!output.contains("── TASK ─"), "{output}");
    assert!(output.contains("triage:run"));
    assert!(output.contains("evidence collect"));
}

#[test]
fn activity_view_renders_dag_rows_and_feed_events() {
    use kuzushi_core::RunTraceStep;

    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::Activity);
    let session = app.activity_mut().unwrap();
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
    assert!(output.contains("semgrep:scan"));
    assert!(output.contains("triage:run"));
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
    run_command(&mut app, ShellCommand::Scene);
    assert_eq!(app.shell_view(), ShellView::Scene);
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
    assert_eq!(viz_page_for_tool("threat-model:build"), None);
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
    app.ui_mut().set_auto_open_viz(true);
    app.auto_open_viz_page(VizPage::Dfd);
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.router.scene().page(), VizPage::Dfd);
}

#[test]
fn auto_open_viz_page_is_inert_when_disabled() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(false);
    let before = app.shell_view().clone();
    app.auto_open_viz_page(VizPage::Dfd);
    assert_eq!(app.shell_view(), before);
}

#[test]
fn auto_open_viz_page_respects_manually_pinned_activity_output() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(true);
    app.set_shell_view(ShellView::Activity);
    app.set_activity(Some(ActivitySession::new("run-viz")));
    app.router
        .activity_mut()
        .set_deck_page_by_user(super::view_state::ActivityDeckPage::Findings);

    app.auto_open_viz_page(VizPage::Dfd);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(
        app.router.activity().deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
}

#[test]
fn auto_open_viz_page_respects_recent_manual_navigation() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(true);
    app.set_shell_view(ShellView::Catalog);
    app.set_input("help");

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert_eq!(app.shell_view(), ShellView::Help);

    app.auto_open_viz_page(VizPage::Dfd);

    assert_eq!(app.shell_view(), ShellView::Help);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "scene"
            && line.body.contains("use `scene` to view")
            && line.body.contains("setg ui.auto_open_viz false")
    }));
}

#[test]
fn scan_completion_auto_opens_the_findings_heatmap() {
    use crate::scene3d::VizPage;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(true);
    let effects = app.apply_scan_finished("run-viz".to_string(), 2);
    EffectRuntime::execute(&mut app, effects);
    assert_eq!(app.shell_view(), ShellView::Scene);
    assert_eq!(app.router.scene().page(), VizPage::Heatmap);
}

#[test]
fn scan_completion_focuses_activity_findings_when_watching_activity() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(true);
    app.set_activity(Some(ActivitySession::new("run-viz")));
    app.set_shell_view(ShellView::Activity);

    let effects = app.apply_scan_finished("run-viz".to_string(), 2);
    EffectRuntime::execute(&mut app, effects);

    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(
        app.router.activity().deck_page,
        super::view_state::ActivityDeckPage::Findings
    );
}

#[test]
fn scan_completion_rehydrates_persisted_taint_flow_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    kuzushi_core::capabilities::save_persistent_taint_flow(
        workspace.root(),
        &serde_json::json!({ "flows": [{
            "cwe": "CWE-89",
            "severity": "high",
            "stages": [
                { "message": "source", "filePath": "src/routes.rs", "line": 12 },
                { "message": "sink", "filePath": "src/db.rs", "line": 44 }
            ]
        }] }),
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.domain_mut().set_taint_flow(None);

    let effects = app.apply_scan_finished("run-viz".to_string(), 1);
    assert!(
        app.domain().taint_flow().is_none(),
        "snapshot hydration should be effect-driven"
    );
    EffectRuntime::execute(&mut app, effects);

    let flow = app.domain().taint_flow().expect("taint flow");
    assert_eq!(flow.cwe, "CWE-89");
    assert_eq!(flow.stages.len(), 2);
}

#[test]
fn scan_finished_event_records_aggregate_cost() {
    let mut app = ShellApp::new(V2Config::default(), None);

    app.apply_scan_event(ScanEvent::Finished {
        run_id: "run-cost".to_string(),
        findings_count: 0,
        cost_usd: Some(0.42),
    });

    assert_eq!(app.session().last_tool_cost_usd(), Some(0.42));
    assert!((app.session().session_cost_usd() - 0.42).abs() < f64::EPSILON);
}

#[test]
fn scan_completion_respects_viz_opt_out() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(false);
    let before = app.shell_view().clone();
    let effects = app.apply_scan_finished("run-viz".to_string(), 2);
    EffectRuntime::execute(&mut app, effects);
    assert_eq!(app.shell_view(), before);
}

#[test]
fn clean_scan_does_not_auto_open_an_empty_heatmap() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ui_mut().set_auto_open_viz(true);
    let before = app.shell_view().clone();
    let effects = app.apply_scan_finished("run-clean".to_string(), 0);
    EffectRuntime::execute(&mut app, effects);
    assert_eq!(
        app.shell_view(),
        before,
        "a 0-finding scan is a pass, not a heatmap to yank to"
    );
}

// --- planning picker confirm honesty (signifier↔state↔intent audit) -------

fn planning_test_row(id: PlanningTaskId, state: PlanningArtifactState) -> PlanningTaskRow {
    PlanningTaskRow {
        id,
        label: id.label(),
        tool_name: id.tool_name(),
        artifact_path: std::path::PathBuf::from("/dev/null"),
        artifact_state: state,
        artifact_modified: None,
        model_backed: id.is_model_backed(),
        required_cli: None,
        cli_available: true,
        blocker: None,
    }
}

fn open_test_planning_picker(app: &mut ShellApp, rows: Vec<PlanningTaskRow>) {
    let selected = rows.iter().map(|row| row.id).collect();
    app.engagement.planning_picker_mut().open(rows, selected);
    app.engagement.set_phase(WorkflowPhase::Map);
    app.set_shell_view(ShellView::PlanningPicker);
}

#[test]
fn confirming_an_all_cached_selection_explains_instead_of_silently_advancing() {
    // Seed disconnect: Enter on a selection whose every row is cached built an
    // empty plan and quietly advanced the phase. It must stay in the picker
    // and say why nothing will run.
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Cached,
        )],
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::PlanningPicker, "stays put");
    assert_eq!(
        app.engagement.current_phase(),
        Some(WorkflowPhase::Map),
        "no phase jump"
    );
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.body.contains("cached and will be reused")),
        "explains the no-op"
    );
}

#[test]
fn confirming_with_nothing_selected_names_the_skipped_phase() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Missing,
        )],
    );
    app.engagement.planning_picker_mut().selected_mut().clear();

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.body.contains("nothing selected — skipping")),
        "names the skip"
    );
    assert_ne!(
        app.engagement.current_phase(),
        Some(WorkflowPhase::Map),
        "an explicit empty selection still advances"
    );
}

#[test]
fn planning_picker_esc_closes_without_recording_skip_or_advancing() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Missing,
        )],
    );

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(!app
        .engagement
        .skipped_phases()
        .contains(&WorkflowPhase::Map));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "phase" && line.body.contains("closed 組 KUMI-KATA") }));
}

#[test]
fn planning_picker_s_records_skip_and_advances_phase() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Missing,
        )],
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::empty()),
    );

    assert!(app
        .engagement
        .skipped_phases()
        .contains(&WorkflowPhase::Map));
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Hunt));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.prefix == "phase" && line.body.contains("skipped 組 KUMI-KATA") }));
}

#[test]
fn planning_picker_number_keys_jump_directly_to_phases_without_running() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Missing,
        )],
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('3'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Confirm));
    assert!(app.engagement.planning_queues_empty());
    assert_eq!(app.engagement.planning_picker().focus(), PickerFocus::List);

    app.engagement
        .planning_picker_mut()
        .set_focus(PickerFocus::OptionsPane);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('1'), KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(app.engagement.planning_queues_empty());
    assert_eq!(app.engagement.planning_picker().focus(), PickerFocus::List);
}

#[test]
fn planning_picker_tab_and_backtab_cycle_list_and_options_focus() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::BuildStrideThreatModel,
            PlanningArtifactState::Missing,
        )],
    );

    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(
        app.engagement.planning_picker().focus(),
        PickerFocus::OptionsPane
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
    );
    assert_eq!(app.engagement.planning_picker().focus(), PickerFocus::List);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
    );
    assert_eq!(
        app.engagement.planning_picker().focus(),
        PickerFocus::OptionsPane
    );

    press_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(app.engagement.planning_picker().focus(), PickerFocus::List);
}

fn open_stride_planning_options_with_model_override(app: &mut ShellApp) -> serde_json::Value {
    open_test_planning_picker(
        app,
        vec![planning_test_row(
            PlanningTaskId::BuildStrideThreatModel,
            PlanningArtifactState::Missing,
        )],
    );
    app.engagement
        .planning_picker_mut()
        .set_focus(PickerFocus::OptionsPane);
    let option_index = app
        .registry()
        .resolve_tool(PlanningTaskId::BuildStrideThreatModel.tool_name())
        .and_then(|tool| tool.options.iter().position(|spec| spec.name == "model"))
        .expect("threat-model model option");
    app.move_planning_option_cursor(option_index as isize);
    let value = serde_json::json!("openai:gpt-5.5");
    app.engagement.set_option_override(
        PlanningTaskId::BuildStrideThreatModel,
        "model".to_string(),
        value.clone(),
    );
    value
}

#[test]
fn planning_option_promote_key_returns_effect_without_persisting() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.replace_option_store_for_test(ToolOptionStore::new());
    app.disable_option_persistence_for_test();
    let expected = open_stride_planning_options_with_model_override(&mut app);
    let before_store = app.option_store().clone();

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('S'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert_eq!(result.effects.len(), 1);
    assert!(matches!(
        &result.effects[0],
        ShellEffect::PersistPlanningOptionOverride(persist)
            if persist.task == PlanningTaskId::BuildStrideThreatModel
                && persist.tool_name == "threat-model:build"
                && persist.option_name == "model"
                && persist.value == expected
    ));
    assert_eq!(app.option_store(), &before_store);
    assert_eq!(
        app.engagement
            .option_override_value(PlanningTaskId::BuildStrideThreatModel, "model"),
        Some(expected)
    );
}

#[test]
fn planning_option_promote_key_executes_effect_when_requested() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.replace_option_store_for_test(ToolOptionStore::new());
    app.disable_option_persistence_for_test();
    let expected = open_stride_planning_options_with_model_override(&mut app);
    let target = OptionTarget::Tool("threat-model:build".to_string());

    let changed = update_and_execute_effects(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Char('S'),
            KeyModifiers::empty(),
        ))),
    );

    assert!(changed);
    assert_eq!(
        app.option_store()
            .values_for(OptionScope::Global, &target)
            .and_then(|values| values.get("model")),
        Some(&expected)
    );
    assert_eq!(
        app.engagement
            .option_override_value(PlanningTaskId::BuildStrideThreatModel, "model"),
        None
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "setg" && line.body.contains("threat-model:build.model")));
}

#[test]
fn planning_picker_accept_returns_dispatch_effect_without_resolving_workspace() {
    let temp = tempfile::tempdir().expect("temp target");
    let missing_target = temp.path().join("missing");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(missing_target.clone()));
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Missing,
        )],
    );

    let result = update(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );

    assert!(result.changed);
    assert_eq!(app.engagement.queued_task_count(), 1);
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    let [ShellEffect::DispatchNextPlanningTask(dispatch)] = result.effects.as_slice() else {
        panic!("expected one planning dispatch effect");
    };
    assert_eq!(dispatch.target.as_deref(), Some(missing_target.as_path()));
    assert_eq!(
        dispatch.missing_workspace_message,
        "cannot run planning queue without an active workspace"
    );
    assert!(matches!(
        &dispatch.success_view,
        Some(PlanningDispatchView::Activity)
    ));
    assert!(!app.log_lines().iter().any(|line| {
        line.prefix == "error"
            && line
                .body
                .contains("cannot run planning queue without an active workspace")
    }));
}

#[test]
fn confirmed_plan_stalled_behind_running_tool_is_announced() {
    // Seed disconnect: Enter while another tool held the background slot queued
    // the plan and returned silently — the operator watched unrelated work run
    // with no hint their plan was waiting.
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.set_running_tool_for_test("semgrep:scan");
    open_test_planning_picker(
        &mut app,
        vec![planning_test_row(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Missing,
        )],
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(
        app.engagement.queued_task_count(),
        1,
        "the confirmed step stays queued"
    );
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.body.contains("waiting for semgrep:scan to finish")),
        "announces the stall: {:?}",
        app.log_lines().iter().map(|l| &l.body).collect::<Vec<_>>()
    );
    assert_eq!(
        app.stalled_planning_steps(),
        1,
        "the Activity header sees the stalled plan"
    );
}

#[test]
fn job_tool_completion_returns_planning_dispatch_effect_without_inline_launch() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_running_tool_for_test("context:build");
    app.engagement.set_running_tool("context:build".to_string());
    app.engagement.queue_plan(vec![PlanningTaskId::ScanSecrets]);

    let result = update(
        &mut app,
        Msg::Job(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "context:build".to_string(),
            result: serde_json::json!({ "output": "context ready" }),
        })),
    );

    assert!(result.changed);
    assert_eq!(app.running_tool_name(), None);
    assert_eq!(app.engagement.running_tool(), None);
    assert_eq!(app.engagement.queued_task_count(), 1);
    assert!(matches!(
        result.effects.as_slice(),
        [
            ShellEffect::RecordToolRun(_),
            ShellEffect::RefreshContextView,
            ShellEffect::DispatchNextPlanningTask(_)
        ]
    ));
}

#[test]
fn recommender_completion_resumes_queued_plan_with_dispatch_effect() {
    let temp = tempfile::tempdir().expect("temp target");
    let missing_target = temp.path().join("missing");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(missing_target.clone()));
    app.set_running_tool_for_test("module-recommender:recommend");
    app.engagement.queue_plan(vec![PlanningTaskId::ScanSecrets]);

    let result = update(
        &mut app,
        Msg::Job(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "module-recommender:recommend".to_string(),
            result: serde_json::json!({
                "output": "recommendations ready",
                "data": {
                    "recommendations": [
                        { "tool": "secrets:scan" }
                    ]
                }
            }),
        })),
    );

    assert!(result.changed);
    assert_eq!(app.running_tool_name(), None);
    assert_eq!(app.engagement.queued_task_count(), 1);
    assert!(matches!(
        result.effects.as_slice(),
        [
            ShellEffect::RecordToolRun(_),
            ShellEffect::DispatchNextPlanningTask(_)
        ]
    ));
    let ShellEffect::DispatchNextPlanningTask(dispatch) = &result.effects[1] else {
        panic!("expected planning dispatch effect");
    };
    assert_eq!(dispatch.target.as_deref(), Some(missing_target.as_path()));
    assert!(!app.log_lines().iter().any(|line| {
        line.prefix == "error"
            && line
                .body
                .contains("planning queue paused: no active workspace")
    }));
}

#[test]
fn job_finding_state_tool_returns_refresh_effect_without_inline_reload() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let store = FindingStore::open(workspace.findings_db_path()).expect("finding store");
    store
        .record_run_started("run-triage", workspace.root(), "completed")
        .expect("record run");
    store
        .insert_finding(
            "run-triage",
            &Finding::new_semgrep(
                "demo.rule",
                "src/lib.rs",
                7,
                None,
                Severity::High,
                "dangerous sink",
            ),
        )
        .expect("persist finding");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.findings_mut().clear();
    app.set_running_tool_for_test("triage:run");

    let result = update(
        &mut app,
        Msg::Job(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "triage:run".to_string(),
            result: serde_json::json!({ "output": "triage complete" }),
        })),
    );

    assert!(result.changed);
    assert!(app.findings().is_empty(), "refresh should be effect-driven");
    assert!(matches!(
        result.effects.as_slice(),
        [
            ShellEffect::RecordToolRun(_),
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None
            })
        ]
    ));
    EffectRuntime::execute(&mut app, result.effects);
    assert_eq!(app.findings().len(), 1);
}

#[test]
fn job_tool_completion_returns_record_tool_effect_without_inline_artifacts() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_active_tool_run_id_for_test("tool-job");
    app.set_running_tool_for_test("semgrep:scan");

    let result = update(
        &mut app,
        Msg::Job(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({ "ok": true, "output": "clean" }),
        })),
    );

    assert!(result.changed);
    assert!(matches!(
        result.effects.as_slice(),
        [ShellEffect::RecordToolRun(_)]
    ));
    let result_path = kuzushi_core::run_dir(workspace.root(), "tool-job").join("result.json");
    assert!(!result_path.exists());
    assert!(!app.log_lines().iter().any(|line| line.prefix == "result"));

    EffectRuntime::execute(&mut app, result.effects);

    assert!(result_path.exists());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("clean")));
}

#[test]
fn job_scan_completion_returns_record_scan_effect_without_inline_artifacts() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("scan-job".to_string()),
        target: workspace.root().to_path_buf(),
        stage: "running semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let result = update(
        &mut app,
        Msg::Job(ShellEvent::Scan(ScanEvent::Finished {
            run_id: "scan-job".to_string(),
            findings_count: 0,
            cost_usd: None,
        })),
    );

    assert!(result.changed);
    assert!(app.scan().is_some_and(|scan| !scan.running));
    assert!(matches!(
        result.effects.as_slice(),
        [
            ShellEffect::RecordScanRun(_),
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None
            }),
            ShellEffect::HydrateSceneSnapshots(_),
            ShellEffect::FinalizeScanCompletion(_)
        ]
    ));
    let events_path = kuzushi_core::run_dir(workspace.root(), "scan-job").join("events.jsonl");
    assert!(!events_path.exists());
    assert!(!app.log_lines().iter().any(|line| line.prefix == "result"));
    EffectRuntime::execute(&mut app, result.effects);
    assert!(events_path.exists());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "result" && line.body.contains("pass")));
}

#[test]
fn job_scan_stage_returns_trace_effect_without_inline_artifact_write() {
    let dir = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(dir.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("scan-stage".to_string()),
        target: workspace.root().to_path_buf(),
        stage: "queued".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_activity(Some(ActivitySession::new("scan-stage")));

    let result = update(
        &mut app,
        Msg::Job(ShellEvent::Scan(ScanEvent::Stage(
            "running semgrep".to_string(),
        ))),
    );

    assert!(result.changed);
    assert_eq!(
        app.scan().map(|scan| scan.stage.as_str()),
        Some("running semgrep")
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "scan" && line.body == "running semgrep"));
    assert!(matches!(
        result.effects.as_slice(),
        [ShellEffect::RecordScanStageTrace(_)]
    ));
    let trace_path = kuzushi_core::run_dir(workspace.root(), "scan-stage").join("trace.jsonl");
    assert!(!trace_path.exists());
    EffectRuntime::execute(&mut app, result.effects);
    let trace = fs::read_to_string(trace_path).expect("trace.jsonl");
    assert!(trace.contains("running semgrep"), "{trace}");
}

#[test]
fn planning_completion_returns_to_workbench_without_auto_recommender() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.set_shell_view(ShellView::Activity);
    app.engagement.clear_phase();

    let effects = app.advance_to_next_phase();

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(effects.is_empty());
    assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    assert_eq!(app.running_tool_name(), None);
    assert!(
        !app.log_lines()
            .iter()
            .any(|line| line.body.contains("module-recommender:recommend")),
        "completion must not auto-run recommender: {:?}",
        app.log_lines().iter().map(|l| &l.body).collect::<Vec<_>>()
    );
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "recommend" && line.body.contains("run `recommend`")));
}

#[test]
fn map_phase_advance_returns_recommendation_refresh_effect_without_inline_launch() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.engagement.set_phase(WorkflowPhase::Map);

    let effects = app.advance_to_next_phase();

    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Hunt));
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::RefreshDeterministicRecommendations(_)]
    ));
    let ShellEffect::RefreshDeterministicRecommendations(refresh) = &effects[0] else {
        panic!("expected deterministic recommendation refresh");
    };
    assert_eq!(refresh.target.as_deref(), Some(dir.path()));
    assert_eq!(app.running_tool_name(), None);
    assert!(
        !app.log_lines()
            .iter()
            .any(|line| line.body.contains("module-recommender:recommend")),
        "phase advancement must not start recommender inline: {:?}",
        app.log_lines()
            .iter()
            .map(|line| &line.body)
            .collect::<Vec<_>>()
    );
}

#[test]
fn phase_advance_does_not_steal_view_when_operator_navigated_away() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.engagement.set_phase(WorkflowPhase::Map);

    app.advance_to_next_phase();

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Hunt));
    let notice = app.advisory().notice.as_ref().expect("phase ready notice");
    assert_eq!(notice.severity, NoticeSeverity::Success);
    assert!(notice.message.contains("KUZUSHI"), "{}", notice.message);
    assert!(notice.message.contains("`next`"), "{}", notice.message);
}

#[test]
fn phase_advance_opens_next_picker_while_operator_watches_activity() {
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.set_shell_view(ShellView::Activity);
    app.engagement.set_phase(WorkflowPhase::Map);

    app.advance_to_next_phase();

    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Hunt));
}

#[test]
fn planning_picker_uppercase_aliases_match_their_advertised_lowercase_keys() {
    // a/A, n/N, Esc/q: the shifted variants are deliberate caps-lock
    // forgiveness for selection and close. `G` is intentionally not a rebuild alias, preserving
    // the shell-wide g/G navigation convention for scrollable views.
    let dir = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    open_test_planning_picker(
        &mut app,
        vec![
            planning_test_row(
                PlanningTaskId::GatherRepoContext,
                PlanningArtifactState::Missing,
            ),
            planning_test_row(PlanningTaskId::BuildXRay, PlanningArtifactState::Cached),
        ],
    );
    app.engagement.planning_picker_mut().selected_mut().clear();

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT),
    );
    assert_eq!(
        app.engagement.planning_picker().selected().len(),
        2,
        "A selects all like a"
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('N'), KeyModifiers::SHIFT),
    );
    assert!(
        app.engagement.planning_picker().selected().is_empty(),
        "N clears like n"
    );

    app.engagement.planning_picker_mut().set_cursor(1); // the cached row
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    assert!(
        app.engagement
            .planning_picker()
            .rebuild()
            .contains(&PlanningTaskId::BuildXRay),
        "g marks cached rows for rebuild"
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    assert!(
        !app.engagement
            .planning_picker()
            .rebuild()
            .contains(&PlanningTaskId::BuildXRay),
        "second g returns cached rows to reuse"
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT),
    );
    assert!(
        !app.engagement
            .planning_picker()
            .rebuild()
            .contains(&PlanningTaskId::BuildXRay),
        "G is not an unadvertised rebuild alias"
    );
    assert!(app.input().is_empty(), "modal picker swallows inert G");

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty()),
    );
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(
        !app.engagement
            .skipped_phases()
            .contains(&WorkflowPhase::Map),
        "q closes like Esc without recording a skip"
    );
}

#[test]
fn empty_prompt_characters_trigger_view_hotkeys_before_text_entry() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = sample_two_findings();

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );

    assert_eq!(app.input(), "");
    assert_eq!(app.router.findings().cursor(), 1);
    assert_eq!(app.input_mode(), crate::InputMode::Prompt);
}

#[test]
fn non_empty_prompt_characters_type_instead_of_triggering_view_hotkeys() {
    let temp = tempfile::tempdir().expect("temp target");
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = sample_two_findings();
    app.set_input("confi");
    app.set_cursor(app.input().len());

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );

    assert_eq!(app.shell_view(), ShellView::Config);
    assert_ne!(app.running_tool_name(), Some("exploit-chain:scan"));
}

#[test]
fn navigate_mode_enables_view_hotkeys_and_esc_returns_to_prompt() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = sample_two_findings();

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::F(2), KeyModifiers::empty()),
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );

    assert_eq!(app.input(), "");
    assert_eq!(app.router.findings().cursor(), 1);
    assert_eq!(app.input_mode(), crate::InputMode::Navigate);

    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), crate::InputMode::Prompt);
}

fn sample_two_findings() -> Vec<kuzushi_core::Finding> {
    vec![
        kuzushi_core::Finding::new_semgrep(
            "demo.a",
            "src/a.rs",
            1,
            Some(1),
            kuzushi_core::Severity::High,
            "first",
        ),
        kuzushi_core::Finding::new_semgrep(
            "demo.b",
            "src/b.rs",
            2,
            Some(2),
            kuzushi_core::Severity::Medium,
            "second",
        ),
    ]
}

// ---- Background jobs registry: steer queue, cancel-by-id, background handoff ----

fn running_scan_panel() -> ScanPanelState {
    ScanPanelState {
        run_id: Some("scan-1".to_string()),
        target: PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }
}

#[test]
fn queue_command_enqueues_a_tool_while_a_job_is_running() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(running_scan_panel()));

    run_command(
        &mut app,
        ShellCommand::QueueCommand("run taint-iris:hunt".to_string()),
    );

    assert_eq!(app.steer_queue().len(), 1);
    assert_eq!(
        app.steer_queue().peek().map(|cmd| cmd.raw.as_str()),
        Some("run taint-iris:hunt")
    );
}

#[test]
fn busy_run_submission_is_queued_instead_of_rejected() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(running_scan_panel()));

    // The operator submit path routes a `run` while busy into the steer queue
    // rather than the old bare rejection.
    app.reduce_submitted_line("run triage:run");

    assert_eq!(app.steer_queue().len(), 1);
    assert_eq!(
        app.steer_queue().peek().map(|cmd| cmd.summary.as_str()),
        Some("run triage:run")
    );
}

#[test]
fn advance_steer_queue_waits_while_work_runs_then_drains_when_idle() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run triage:run".to_string(),
        summary: "run triage:run".to_string(),
    });

    // Work still running: steer item must wait, never pre-empt.
    app.set_scan_panel(Some(running_scan_panel()));
    let held = app.advance_steer_queue();
    assert!(held.is_empty());
    assert_eq!(app.steer_queue().len(), 1);

    // Idle: the queued item drains.
    app.set_scan_panel(None);
    let _ = app.advance_steer_queue();
    assert!(app.steer_queue().is_empty());
}

#[test]
fn queued_steer_item_dispatches_when_a_scan_finishes() {
    // Regression: the drain must run on the scan-completion path, not only on a
    // successful background-tool finish. scan running -> queue a run -> scan
    // finishes -> the queued item leaves the queue.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(running_scan_panel()));
    let _ticket = app.jobs_mut().start(JobKind::Run, "scan");
    app.set_activity(Some(ActivitySession::new("scan-1")));

    run_command(
        &mut app,
        ShellCommand::QueueCommand("run triage:run".to_string()),
    );
    assert_eq!(app.steer_queue().len(), 1);

    // The scan's terminal event flows through the central drain in
    // `apply_job_event`.
    let _effects = app.apply_job_event(ShellEvent::Scan(ScanEvent::Finished {
        run_id: "scan-1".to_string(),
        findings_count: 0,
        cost_usd: None,
    }));

    assert!(!app.scan().is_some_and(|scan| scan.running));
    assert!(
        app.steer_queue().is_empty(),
        "queued steer item must dispatch when the scan finishes"
    );
}

#[test]
fn advance_steer_queue_yields_to_a_pending_planning_queue() {
    // chain -> plan -> steer: while the planning queue still has steps (whose
    // dispatch is deferred through DispatchNextPlanningTask), the steer item
    // must stay queued or it would be popped and then dropped by the overlap
    // reject.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run triage:run".to_string(),
        summary: "run triage:run".to_string(),
    });
    app.engagement
        .queue_plan(vec![crate::app::PlanningTaskId::GatherRepoContext]);
    assert!(!app.engagement.planning_queues_empty());

    let effects = app.advance_steer_queue();

    assert!(effects.is_empty());
    assert_eq!(app.steer_queue().len(), 1);
}

#[test]
fn advance_steer_queue_yields_to_a_pending_prereq_chain() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run triage:run".to_string(),
        summary: "run triage:run".to_string(),
    });
    // A prereq chain is pending (chain -> plan -> steer precedence): the steer
    // item must stay queued for the chain to finish first.
    app.engagement.set_pending_chain(PrereqChain::new(
        Vec::new(),
        "carlini-threat-hunt:run".to_string(),
        serde_json::Value::Null,
        None,
    ));

    let effects = app.advance_steer_queue();

    assert!(effects.is_empty());
    assert_eq!(app.steer_queue().len(), 1);
}

#[test]
fn cancel_job_dequeues_a_pending_steer_item() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run a".to_string(),
        summary: "run a".to_string(),
    });
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run b".to_string(),
        summary: "run b".to_string(),
    });

    run_command(&mut app, ShellCommand::CancelJob("queued-1".to_string()));

    assert_eq!(app.steer_queue().len(), 1);
    assert_eq!(
        app.steer_queue().peek().map(|cmd| cmd.raw.as_str()),
        Some("run b")
    );
}

#[test]
fn cancel_job_scopes_cancellation_to_the_addressed_live_run() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let _ticket = app.jobs_mut().start(JobKind::Run, "triage:run");
    app.set_activity(Some(ActivitySession::new("tool-abc")));

    let effects = app
        .reduce_command_effects(&ShellCommand::CancelJob("tool-abc".to_string()))
        .expect("cancel-job routes");

    // Scoped: cancels only the addressed Run slot, not every concurrent job.
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::CancelJob(JobKind::Run)]
    ));
}

#[test]
fn cancel_job_unknown_id_does_not_fire_a_token() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let effects = app
        .reduce_command_effects(&ShellCommand::CancelJob("scan-999".to_string()))
        .expect("cancel-job routes");

    // Nothing live and no queued item: report honestly, emit no cancel effect.
    assert!(effects.is_empty());
}

#[test]
fn background_handoff_shows_workbench_without_cancelling_live_work() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(running_scan_panel()));

    run_command(&mut app, ShellCommand::Background);

    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.has_running_work());
    assert!(!app.scan().is_some_and(|scan| scan.abort_requested));
}

#[test]
fn jobs_verb_opens_the_jobs_registry_view() {
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, ShellCommand::ShowJobs);
    assert_eq!(app.shell_view(), ShellView::Jobs);
}
