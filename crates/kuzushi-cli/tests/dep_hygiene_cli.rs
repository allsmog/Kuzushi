use std::process::Command;

use kuzushi_core::{
    Finding, FindingStore, ReconWorkspaceStore, Severity, TriageOutcome, TriageVerdict,
    WorkspaceTarget,
};
use serde_json::Value;

fn kuzushi_command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kuzushi"));
    command
        .env("HOME", home)
        .env_remove("KUZUSHI_MODEL")
        .env_remove("KUZUSHI_V2_MODEL")
        .env_remove("KUZUSHI_API_KEY_ENV")
        .env_remove("KUZUSHI_V2_API_KEY_ENV")
        .env_remove("KUZUSHI_BASE_URL")
        .env_remove("KUZUSHI_V2_BASE_URL")
        .env_remove("KUZUSHI_LANGGRAPH_BRIDGE")
        .env_remove("KUZUSHI_V2_LANGGRAPH_BRIDGE");
    command
}

fn latest_run_id(repo: &std::path::Path) -> String {
    std::fs::read_to_string(repo.join(".kuzushi/v3/latest"))
        .unwrap()
        .trim()
        .to_string()
}

fn run_json(repo: &std::path::Path, run_id: &str, leaf: &str) -> Value {
    let path = repo.join(".kuzushi/v3/runs").join(run_id).join(leaf);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn latest_run_json(repo: &std::path::Path, leaf: &str) -> Value {
    run_json(repo, &latest_run_id(repo), leaf)
}

fn assert_latest_canonical_run_bundle(repo: &std::path::Path) {
    let run_id = latest_run_id(repo);
    let run_dir = repo.join(".kuzushi/v3/runs").join(&run_id);
    for leaf in [
        "run.json",
        "events.jsonl",
        "trace.jsonl",
        "failures.json",
        "report.md",
        "artifacts.json",
    ] {
        assert!(
            run_dir.join(leaf).exists(),
            "latest run {run_id} missing canonical artifact {leaf}"
        );
    }
    for leaf in [
        "context.json",
        "attack-surface.json",
        "threat-model.json",
        "recommendations.json",
        "findings.json",
        "proof.json",
    ] {
        assert!(
            !run_dir.join(leaf).exists(),
            "latest run {run_id} wrote retired v2 artifact {leaf}"
        );
    }

    let run = run_json(repo, &run_id, "run.json");
    assert_eq!(run.get("status").and_then(Value::as_str), Some("completed"));

    let failures = run_json(repo, &run_id, "failures.json");
    assert_eq!(
        failures.get("status").and_then(Value::as_str),
        Some("completed")
    );
    assert!(failures
        .get("failures")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty));
}

fn assert_latest_static_artifacts(repo: &std::path::Path, expected_tool: &str) {
    assert_latest_canonical_run_bundle(repo);

    let result = latest_run_json(repo, "result.json");
    let finding = result
        .pointer("/data/coreFindings/0")
        .or_else(|| result.pointer("/coreFindings/0"))
        .or_else(|| result.pointer("/data/findings/0"))
        .expect("tool result should carry at least one finding");
    assert_eq!(
        finding.get("tool").and_then(Value::as_str),
        Some(expected_tool)
    );
    assert_eq!(
        finding.get("staticProofState").and_then(Value::as_str),
        Some("signal_only")
    );

    let artifacts = latest_run_json(repo, "artifacts.json");
    let artifact_labels = artifacts
        .pointer("/artifacts")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|artifact| artifact.pointer("/label").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(artifact_labels.contains(&"tool result"));
    assert!(!artifact_labels.contains(&"findings"));
    assert!(!artifact_labels.contains(&"proof"));
}

fn write_systems_hunt_fixture(repo: &std::path::Path) {
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(
        repo.join("src/parser.c"),
        "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
    )
    .unwrap();
}

fn seed_true_positive_finding(repo: &std::path::Path) -> String {
    let workspace = WorkspaceTarget::new(repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-seeded", workspace.root(), "running")
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
    let finding_id = store.insert_finding("run-seeded", &finding).unwrap();
    store
        .record_auto_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.93,
                rationale: "request body reaches exec".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    store
        .record_run_finished("run-seeded", "completed", 1)
        .unwrap();
    fingerprint
}

#[cfg(unix)]
fn fake_semgrep_binary(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("semgrep");
    std::fs::write(
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
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
}

#[cfg(unix)]
fn fake_codeql_binary(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("codeql");
    std::fs::write(
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
  "version": "2.1.0",
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
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
}

#[cfg(unix)]
fn fake_curl_binary(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("curl");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
case "$*" in
  *crt.sh*)
    cat <<'JSON'
[{"name_value":"www.example.com\napi.example.com"}]
JSON
    ;;
  *)
    cat <<'HTTP'
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express

<html><title>Acme</title></html>
HTTP
    ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
}

#[cfg(unix)]
fn fake_nmap_binary(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("nmap");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat <<'OUT'
Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/
OUT
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
}

#[cfg(unix)]
fn fake_triage_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("triage-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"verdict":"true_positive","confidence":0.93,"rationale":"mock cli bridge"}}
JSON
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_agentic_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("agentic-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"agentic/sql-injection","filePath":"src/db.ts","startLine":1,"severity":"ERROR","message":"User input reaches SQL query","confidence":"HIGH","evidence":"Source: req.query.q -> sink: db.query"}]}}
JSON
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_variant_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("variant-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Variant Hunter pattern lifter"*)
    cat <<'JSON'
{"ok":true,"structured":{"source":"HTTP request body","sink":"child_process.exec","missingGuard":"no allowlist","languages":["typescript"],"keywords":["exec","child_process"],"description":"Untrusted input reaches shell execution."}}
JSON
    ;;
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
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_ndiff_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("ndiff-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"N-day fix-pattern extractor"*)
    cat <<'JSON'
{"ok":true,"structured":{"fixShape":"adds a bounds check before memcpy","vulnerableShape":"memcpy uses attacker-controlled length without a bounds check","cwe":["CWE-787"],"languages":["c"],"keywords":["memcpy","len"],"detectionQuery":"rg 'memcpy\\('","description":"Search copies guarded by no length cap.","confidence":"HIGH"}}
JSON
    ;;
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
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_taint_iris_next_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("taint-iris-next-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Taint IRIS Next agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"selectedCwes":[{"cwe":"CWE-89","reason":"raw query receives request data","catalogSignals":["sink: query("],"sourceSpec":"request query parameters","sinkSpec":"database query calls","sanitizerSpec":"parameterized query APIs","customCweRationale":""}],"findings":[{"title":"Request parameter reaches raw SQL query","cwe":"CWE-89","severity":"high","confidence":"medium","evidenceLevel":"linked","filePath":"src/routes.ts","startLine":1,"message":"The query uses request-controlled data in SQL construction.","sourceSinkTrace":"req.query.id -> db.query(sql)","catalogSignals":["source: req.query","sink: query("],"customCweRationale":"","taintPath":[{"filePath":"src/routes.ts","line":1,"message":"source and SQL sink","snippet":"db.query(req.query.id)"}]}],"triage":[{"status":"finding","cwe":"CWE-89","evidenceLevel":"linked","rationale":"request data reaches raw SQL query","filePath":"src/routes.ts","line":1,"catalogSignals":["sink: query("]}],"notes":[]}}
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
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_carlini_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("carlini-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"carlini-threat-hunt/actor-xss","filePath":"src/app.ts","startLine":9,"severity":"ERROR","message":"Actor-controlled input reaches HTML response","confidence":"HIGH","evidence":"Source: request query -> sink: response HTML"}]}}
JSON
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_systems_hunt_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("systems-hunt-bridge.sh");
    std::fs::write(
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
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_verify_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("verify-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"fingerprint":"fp-from-bridge","exploitable":true,"poc_payload":"curl -X POST /admin","poc_description":"POST reaches admin sink","attack_vector":"curl POST /admin","preconditions":["network access"],"confidence":0.84,"proof_level":3,"proof_verdict":"exploited"}}
JSON
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_patch_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("patch-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"diff":"--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n","explanation":"sanitize query input"}}
JSON
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_sast_full_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("sast-full-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"agentic SAST scanner"*)
    cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"agentic/sql-injection","filePath":"src/db.ts","startLine":1,"severity":"ERROR","message":"User input reaches SQL query","confidence":"HIGH","evidence":"Source: req.query.q -> sink: db.query"}]}}
JSON
    ;;
  *"security triage agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"verdict":"true_positive","confidence":0.93,"rationale":"mock cli bridge"}}
JSON
    ;;
  *"exploitability verifier"*)
    cat <<'JSON'
{"ok":true,"structured":{"exploitable":true,"poc_payload":"curl -X POST /admin","poc_description":"POST reaches admin sink","attack_vector":"curl POST /admin","preconditions":["network access"],"confidence":0.84,"proof_level":3,"proof_verdict":"exploited"}}
JSON
    ;;
  *"security patch planner"*)
    cat <<'JSON'
{"ok":true,"structured":{"diff":"--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n","explanation":"sanitize query input"}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected request"}'
    exit 1
    ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[cfg(unix)]
fn fake_x_ray_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("x-ray-bridge.sh");
    std::fs::write(
        &binary,
        r##"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"xRayMarkdown":"# X-Ray\n\n## X-Ray Verdict\nWATCH\nReview invariants before launch.\n","entryPointsMarkdown":"# Entry Points\n\n> App | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n","invariantsMarkdown":"# Invariants\n\n### G-1 Balance conservation\n","architectureSvg":"<svg xmlns=\"http://www.w3.org/2000/svg\" />\n"}}
JSON
"##,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

fn write_x_ray_fixture(repo: &std::path::Path) {
    let dir = repo.join("x-ray");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("x-ray.md"),
        "# X-Ray\n\n## X-Ray Verdict\nREADY\nReviewable surface.\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("entry-points.md"),
        "# Entry Points\n\n> App | 2 entry points | 1 permissionless | 1 role-gated | 0 admin-only\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("invariants.md"),
        "# Invariants\n\n### G-1 Balance\n### I-1 Oracle\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("architecture.svg"),
        r#"<svg xmlns="http://www.w3.org/2000/svg" />"#,
    )
    .unwrap();
}

fn write_carlini_threat_model_fixture(repo: &std::path::Path) {
    let threat_model_path = kuzushi_core::capabilities::persistent_threat_model_path(repo);
    std::fs::create_dir_all(threat_model_path.parent().unwrap()).unwrap();
    std::fs::write(
        threat_model_path,
        r#"{"version":"2.0","dfd":{"nodes":[{"id":"actor-user","type":"external-entity","name":"Authenticated User","description":"External authenticated user","trustZone":"external"},{"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}],"flows":[{"id":"flow-1","sourceId":"actor-user","targetId":"web","description":"profile request","trustBoundaryIds":["tb-1"],"protocol":"https"}],"trustBoundaries":[{"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}]},"threats":[{"id":"T-001","actorIds":["actor-user"],"flowIds":["flow-1"],"targetElementIds":["web"],"category":"tampering","title":"Profile HTML injection","description":"query reaches HTML","attackVector":"crafted profile query","impact":"high","likelihood":"medium","affectedFiles":[{"filePath":"src/app.ts","startLine":9}]}],"summary":{"total":1,"bySeverity":{"high":1},"byCategory":{"tampering":1}}}"#,
    )
    .unwrap();
}

#[cfg(unix)]
fn fake_threat_model_bridge(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = dir.join("threat-model-bridge.sh");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"document":{"version":"2.0","dfd":{"nodes":[{"id":"actor-user","type":"external-entity","name":"User","description":"External user","trustZone":"external"},{"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}],"flows":[{"id":"flow-1","description":"request","sourceId":"actor-user","targetId":"web","trustBoundaryIds":["tb-1"]}],"trustBoundaries":[{"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}]},"threats":[{"id":"T-001","targetElementIds":["web"],"category":"spoofing","title":"Spoofed login","description":"stolen token","attackVector":"token theft","preconditions":[],"impact":"high","likelihood":"medium","existingMitigations":[],"missingMitigations":["bind sessions"],"relatedCwe":["CWE-287"],"affectedFiles":[{"filePath":"src/auth.ts","startLine":1}]}],"summary":{"total":1,"bySeverity":{"high":1},"byCategory":{"spoofing":1}}}}}
JSON
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).unwrap();
    binary
}

#[test]
fn run_dep_hygiene_check_reaches_native_executor() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"lodash":"latest","react":"^18.2.0"}}"#,
    )
    .unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("dep-hygiene:check")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/packageName")
            .and_then(Value::as_str),
        Some("lodash")
    );
    assert!(body
        .get("output")
        .and_then(Value::as_str)
        .is_some_and(|output| output.contains("dep-hygiene: 1 risky specifier")));
    assert_latest_static_artifacts(&repo, "dep-hygiene");
}

#[test]
fn run_report_build_promotes_markdown_for_report_run() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();

    let scan = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("dep-hygiene:check")
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let source_run = latest_run_id(&repo);

    let report = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("report:build")
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let body: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(
        body.pointer("/data/sourceRunId").and_then(Value::as_str),
        Some(source_run.as_str())
    );
    assert!(body
        .pointer("/reportMarkdown")
        .and_then(Value::as_str)
        .is_some_and(|markdown| markdown.contains("dep-hygiene:check")));

    let report_run = latest_run_id(&repo);
    assert_ne!(report_run, source_run);
    assert_eq!(
        run_json(&repo, &report_run, "run.json")
            .pointer("/tool")
            .and_then(Value::as_str),
        Some("report:build")
    );
    let report_markdown = std::fs::read_to_string(
        repo.join(".kuzushi/v3/runs")
            .join(&report_run)
            .join("report.md"),
    )
    .unwrap();
    assert!(report_markdown.contains(source_run.as_str()));
    assert!(report_markdown.contains("dep-hygiene:check"));
    assert!(run_json(&repo, &report_run, "artifacts.json")
        .pointer("/artifacts")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .any(|artifact| artifact.pointer("/label").and_then(Value::as_str) == Some("report")));
}

#[test]
fn run_report_build_surfaces_failed_source_handoff() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let failed_scan = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("semgrep:scan")
        .arg("--input")
        .arg(format!(
            r#"{{"binary":"{}"}}"#,
            temp.path().join("missing-semgrep").display()
        ))
        .output()
        .unwrap();
    assert!(!failed_scan.status.success());
    let source_run = latest_run_id(&repo);

    let report = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("report:build")
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let body: Value = serde_json::from_slice(&report.stdout).unwrap();
    let markdown = body
        .pointer("/reportMarkdown")
        .and_then(Value::as_str)
        .unwrap();
    assert_eq!(
        body.pointer("/data/sourceRunId").and_then(Value::as_str),
        Some(source_run.as_str())
    );
    assert!(markdown.contains("## Failure Handoff"));
    assert!(markdown.contains("Failed Stage: semgrep:scan"));
    assert!(markdown.contains("artifact-review-only"));
    assert!(markdown.contains("Fallback Prompt"));
    assert!(!markdown.contains("validated"));

    let report_run = latest_run_id(&repo);
    let report_markdown = std::fs::read_to_string(
        repo.join(".kuzushi/v3/runs")
            .join(&report_run)
            .join("report.md"),
    )
    .unwrap();
    assert!(report_markdown.contains("## Failure Handoff"));
    assert!(report_markdown.contains(source_run.as_str()));
    assert!(!report_markdown.contains("validated"));
}

#[test]
fn run_dep_hygiene_check_missing_target_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .current_dir(&repo)
        .arg("run")
        .arg("dep-hygiene:check")
        .arg("--input")
        .arg(r#"{"target":"missing"}"#)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Target path does not exist: missing"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_latest_failed_run_bundle(repo: &std::path::Path, expected_tool: &str, error: &str) {
    let run_id = latest_run_id(repo);
    let run = run_json(repo, &run_id, "run.json");
    let failures = run_json(repo, &run_id, "failures.json");
    let result = run_json(repo, &run_id, "result.json");

    assert_eq!(run.get("status").and_then(Value::as_str), Some("failed"));
    assert_eq!(run.get("tool").and_then(Value::as_str), Some(expected_tool));
    assert_eq!(
        failures.get("status").and_then(Value::as_str),
        Some("failed")
    );
    assert!(failures.to_string().contains(error));
    assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
    assert!(result.to_string().contains(error));
}

#[test]
fn run_context_build_writes_compatible_snapshot_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"express":"^4.18.0","jsonwebtoken":"^9.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(repo.join("src/server.ts"), "export const app = {};\n").unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("context:build")
        .arg("--input")
        .arg(r#"{"sampleLimit":10,"scope":"repo"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/snapshot/discovery")
            .and_then(Value::as_str),
        Some("auto")
    );
    assert_eq!(
        body.pointer("/data/snapshot/repoContext/frameworks/0")
            .and_then(Value::as_str),
        Some("express")
    );
    assert_eq!(
        body.pointer("/data/snapshot/staleSlices/0")
            .and_then(Value::as_str),
        Some("enrichment")
    );

    let snapshot_path = kuzushi_core::context::context_snapshot_path(&repo);
    let snapshot: Value = serde_json::from_slice(&std::fs::read(snapshot_path).unwrap()).unwrap();
    assert_eq!(
        snapshot
            .pointer("/repoContext/authPatterns/0")
            .and_then(Value::as_str),
        Some("jwt")
    );
    assert_eq!(
        snapshot
            .pointer("/fileIndex/totalFiles")
            .and_then(Value::as_u64),
        Some(2)
    );
}

#[test]
fn run_secret_scan_reaches_native_executor_and_writes_canonical_findings() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("config.env"),
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
    )
    .unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("secret-scan:scan")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/findings/0/ruleId")
            .and_then(Value::as_str),
        Some("secret-scan/openai-api-key")
    );
    assert!(body
        .pointer("/data/findings/0/evidence")
        .and_then(Value::as_str)
        .is_some_and(|evidence| evidence.contains("sk-p********")));

    assert_latest_static_artifacts(&repo, "secret-scan");
}

#[test]
fn run_secret_scan_missing_target_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .current_dir(&repo)
        .arg("run")
        .arg("secret-scan:scan")
        .arg("--input")
        .arg(r#"{"target":"missing"}"#)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Target path does not exist: missing"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_iac_scan_reaches_native_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("main.tf"), "cidr_blocks = [\"0.0.0.0/0\"]\n").unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("iac-scan:scan")
        .arg("--input")
        .arg(r#"{"kind":"terraform"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/ruleId")
            .and_then(Value::as_str),
        Some("iac-scan/terraform-public-ingress")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
    assert_latest_static_artifacts(&repo, "iac-scan");
}

#[test]
fn scan_tasks_iac_scan_reaches_scan_engine_path() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("main.tf"), "cidr_blocks = [\"0.0.0.0/0\"]\n").unwrap();

    let output = kuzushi_command(&home)
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("iac-scan")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));
    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "iac-scan");
}

#[test]
fn run_iac_scan_missing_target_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .current_dir(&repo)
        .arg("run")
        .arg("iac-scan:scan")
        .arg("--input")
        .arg(r#"{"target":"missing"}"#)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Target path does not exist: missing"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_sast_scan_reaches_scan_runner_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("config.env"),
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
    )
    .unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("sast:scan")
        .arg("--input")
        .arg(r#"{"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/findingsCount").and_then(Value::as_u64),
        Some(2)
    );
    assert!(body
        .pointer("/data/db")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn run_agentic_sast_scan_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
    let bridge = fake_agentic_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("agentic-sast:scan")
        .arg("--input")
        .arg(r#"{"maxFindings":5}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("agentic/sql-injection")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "agentic");
}

#[cfg(unix)]
#[test]
fn scan_tasks_agentic_reaches_same_agentic_executor() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
    let bridge = fake_agentic_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("agentic")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "agentic");
}

#[cfg(unix)]
#[test]
fn run_variant_lift_pattern_reaches_langgraph_runtime_bridge() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
    let fingerprint = seed_true_positive_finding(&repo);
    let bridge = fake_variant_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("variant:lift-pattern")
        .arg("--input")
        .arg(format!(r#"{{"fingerprint":"{fingerprint}"}}"#))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/signature/sink").and_then(Value::as_str),
        Some("child_process.exec")
    );
}

#[cfg(unix)]
#[test]
fn run_variant_hunt_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
    std::fs::write(repo.join("src/other.ts"), "exec(req.body.other)\n").unwrap();
    let fingerprint = seed_true_positive_finding(&repo);
    let bridge = fake_variant_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("variant:hunt")
        .arg("--input")
        .arg(format!(
            r#"{{"fingerprint":"{fingerprint}","maxFindings":5}}"#
        ))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/variants")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        body.pointer("/data/variants/0/tool")
            .and_then(Value::as_str),
        Some("variant-analysis")
    );

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding.tool == "variant-analysis"));
}

#[cfg(unix)]
#[test]
fn run_ndiff_extract_fix_pattern_reaches_langgraph_runtime_bridge() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let bridge = fake_ndiff_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("ndiff:extract-fix-pattern")
        .arg("--input")
        .arg(r#"{"patchText":"--- a/parser.c\n+++ b/parser.c\n+if (len > cap) return -1;\n"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/pattern/vulnerableShape")
            .and_then(Value::as_str),
        Some("memcpy uses attacker-controlled length without a bounds check")
    );
}

#[cfg(unix)]
#[test]
fn run_ndiff_hunt_variants_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/parser.c"), "memcpy(dst, src, len);\n").unwrap();
    let bridge = fake_ndiff_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("ndiff:hunt-variants")
        .arg("--input")
        .arg(r#"{"advisoryId":"CVE-2024-1234","pattern":{"fixShape":"adds a bounds check before memcpy","vulnerableShape":"memcpy uses attacker-controlled length without a bounds check","cwe":["CWE-787"],"languages":["c"],"keywords":["memcpy","len"],"detectionQuery":"rg 'memcpy\\('","description":"Search copies guarded by no length cap.","confidence":"HIGH"}}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/findings")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("n-day/CVE-2024-1234")
    );

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding.tool == "n-day-diff-hunter"));
}

#[test]
fn run_ndiff_fetch_cve_uses_offline_fixture_without_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("ndiff:fetch-cve")
        .arg("--input")
        .arg(r#"{"id":"CVE-2024-1234","offline":true,"fixtures":{"CVE-2024-1234":{"id":"CVE-2024-1234","description":"Missing bounds check allows OOB write.","cwes":["CWE-787"],"severity":"HIGH","cvssScore":7.8,"affected":[],"patches":[{"url":"https://github.com/o/r/commit/abc1234","kind":"nvd"}],"publishedAt":"2024-01-15T00:00:00.000Z","source":"nvd","raw":{}}}}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/primaryPatchUrl")
            .and_then(Value::as_str),
        Some("https://github.com/o/r/commit/abc1234")
    );
}

#[test]
fn run_variant_hunt_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
    let fingerprint = seed_true_positive_finding(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("variant:hunt")
        .arg("--input")
        .arg(format!(r#"{{"fingerprint":"{fingerprint}"}}"#))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
    assert_latest_failed_run_bundle(&repo, "variant:hunt", "requires an explicit model");
}

#[test]
fn run_ndiff_hunt_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("ndiff:hunt-variants")
        .arg("--input")
        .arg(r#"{"pattern":{"fixShape":"guard","vulnerableShape":"unguarded"}}"#)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
    assert_latest_failed_run_bundle(&repo, "ndiff:hunt-variants", "requires an explicit model");
}

#[cfg(unix)]
#[test]
fn run_taint_iris_hunt_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("src/routes.ts"),
        "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
    )
    .unwrap();
    let bridge = fake_taint_iris_next_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("taint-iris:hunt")
        .arg("--input")
        .arg(r#"{"maxFindings":5,"mcps":false}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/status").and_then(Value::as_str),
        Some("hunted")
    );
    assert_eq!(
        body.pointer("/data/selectedCwes/0/cwe")
            .and_then(Value::as_str),
        Some("CWE-89")
    );
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("taint-iris-next/cwe-89")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
}

#[cfg(unix)]
#[test]
fn scan_tasks_taint_iris_reaches_same_taint_iris_executor() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    seed_taint_iris_next_mcp_artifacts(&repo);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("src/routes.ts"),
        "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
    )
    .unwrap();
    let bridge = fake_taint_iris_next_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("taint-iris")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
}

#[cfg(unix)]
#[test]
fn run_taint_iris_next_hunt_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    seed_taint_iris_next_mcp_artifacts(&repo);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("src/routes.ts"),
        "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
    )
    .unwrap();
    let bridge = fake_taint_iris_next_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("taint-iris-next:hunt")
        .arg("--input")
        .arg(
            r#"{"mode":"hunt","maxCatalogEntries":3,"maxAgentFindings":5,"minEvidenceLevel":"candidate","mcps":false}"#,
        )
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/status").and_then(Value::as_str),
        Some("hunted")
    );
    assert_eq!(
        body.pointer("/data/selectedCwes/0/cwe")
            .and_then(Value::as_str),
        Some("CWE-89")
    );
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("taint-iris-next/cwe-89")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
}

#[cfg(unix)]
#[test]
fn scan_tasks_taint_iris_next_reaches_same_taint_iris_next_executor() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    seed_taint_iris_next_mcp_artifacts(&repo);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("src/routes.ts"),
        "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
    )
    .unwrap();
    // hunt mode refuses to dispatch without the joern/codeql artifacts; the
    // bridge is faked, so stub them.
    std::fs::create_dir_all(repo.join(".kuzushi/codeql-db")).unwrap();
    std::fs::write(repo.join(".kuzushi/codeql-db/placeholder"), "stub").unwrap();
    std::fs::write(repo.join(".kuzushi/cpg.bin"), "stub").unwrap();
    let bridge = fake_taint_iris_next_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("taint-iris-next")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
}

#[cfg(unix)]
#[test]
fn run_carlini_threat_hunt_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("src/app.ts"),
        "res.send(`<p>${req.query.name}</p>`)\n",
    )
    .unwrap();
    write_carlini_threat_model_fixture(&repo);
    let bridge = fake_carlini_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("carlini-threat-hunt:run")
        .arg("--input")
        .arg(r#"{"maxActors":1,"runsPerActor":1}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("carlini-threat-hunt/actor-xss")
    );
    assert_eq!(
        body.pointer("/data/findings/0/actor_fingerprint")
            .and_then(Value::as_str),
        Some("carlini-threat-hunt:Authenticated_User:0")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "carlini-threat-hunt");
}

#[cfg(unix)]
#[test]
fn scan_tasks_carlini_reaches_same_carlini_executor() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("src/app.ts"),
        "res.send(`<p>${req.query.name}</p>`)\n",
    )
    .unwrap();
    write_carlini_threat_model_fixture(&repo);
    let bridge = fake_carlini_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("carlini-threat-hunt")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "carlini-threat-hunt");
}

#[cfg(unix)]
#[test]
fn run_systems_hunt_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    write_systems_hunt_fixture(&repo);
    let bridge = fake_systems_hunt_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("systems-hunt:systems-hunt")
        .arg("--input")
        .arg(r#"{"maxFindings":5}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("systems-hunt/cwe-787")
    );
    assert!(body
        .pointer("/data/artifacts/0")
        .and_then(Value::as_str)
        .is_some_and(|path| path.starts_with(".kuzushi/systems-hunt/")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "systems-hunt");
}

#[cfg(unix)]
#[test]
fn scan_tasks_systems_hunt_reaches_same_executor() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    write_systems_hunt_fixture(&repo);
    let bridge = fake_systems_hunt_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("systems-hunt")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "systems-hunt");
}

#[test]
fn run_carlini_threat_hunt_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    write_carlini_threat_model_fixture(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("carlini-threat-hunt:run")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
    assert_latest_failed_run_bundle(
        &repo,
        "carlini-threat-hunt:run",
        "requires an explicit model",
    );
}

#[test]
fn run_agentic_sast_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("agentic-sast:scan")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires an explicit model")
            || String::from_utf8_lossy(&output.stderr).contains("requires the langgraph runtime"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_systems_hunt_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    write_systems_hunt_fixture(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("systems-hunt:systems-hunt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
    assert_latest_failed_run_bundle(
        &repo,
        "systems-hunt:systems-hunt",
        "requires an explicit model",
    );
}

#[test]
fn run_taint_iris_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/routes.ts"), "db.query(req.query.id)\n").unwrap();
    let bridge = fake_taint_iris_next_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("taint-iris:hunt")
        .arg("--input")
        .arg(r#"{"mcps":false}"#)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires an explicit model")
            || String::from_utf8_lossy(&output.stderr).contains("requires the langgraph runtime"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_taint_iris_next_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/routes.ts"), "db.query(req.query.id)\n").unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("taint-iris-next:hunt")
        .arg("--input")
        .arg(r#"{"mode":"hunt","maxCatalogEntries":5}"#)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires an explicit model")
            || String::from_utf8_lossy(&output.stderr).contains("requires the langgraph runtime"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn run_sast_scan_verify_autopatch_writes_run_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/db.ts"), "const query = req.query.q;\n").unwrap();
    init_git_repo(&repo);
    let bridge = fake_sast_full_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("sast:scan")
        .arg("--input")
        .arg(
            r#"{"taskMode":"manual","tasks":["agentic"],"verify":true,"autoPatch":true,"maxIterations":1,"buildCmd":"true","testCmd":"true"}"#,
        )
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        body.pointer("/data/verification/verified")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        body.pointer("/data/patch/patched").and_then(Value::as_u64),
        Some(1)
    );
    let summary = body
        .pointer("/data/artifacts/summary")
        .and_then(Value::as_str)
        .unwrap();
    let triage_log = body
        .pointer("/data/artifacts/triageJsonl")
        .and_then(Value::as_str)
        .unwrap();
    let verify_log = body
        .pointer("/data/artifacts/verifyJsonl")
        .and_then(Value::as_str)
        .unwrap();
    let patch_log = body
        .pointer("/data/artifacts/patchJsonl")
        .and_then(Value::as_str)
        .unwrap();
    assert!(std::path::Path::new(summary).exists());
    assert!(std::fs::read_to_string(summary)
        .unwrap()
        .contains("\"patch\""));
    assert!(std::fs::read_to_string(triage_log)
        .unwrap()
        .contains("triage:complete"));
    assert!(!std::fs::read_to_string(verify_log)
        .unwrap()
        .contains("patch:complete"));
    assert!(std::fs::read_to_string(patch_log)
        .unwrap()
        .contains("patch:complete"));
}

#[cfg(unix)]
#[test]
fn run_semgrep_scan_reaches_subprocess_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();
    std::fs::write(repo.join("server.js"), "res.send(req.query.x)\n").unwrap();
    fake_semgrep_binary(&fake_bin);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_bin.display(), old_path.to_string_lossy());
    let output = kuzushi_command(&home)
        .env("PATH", path)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("semgrep:scan")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("javascript.express.security.audit.xss")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
    assert_latest_static_artifacts(&repo, "semgrep");
}

#[test]
fn run_semgrep_scan_missing_binary_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("semgrep:scan")
        .arg("--input")
        .arg(format!(
            r#"{{"binary":"{}"}}"#,
            temp.path().join("missing-semgrep").display()
        ))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("semgrep:scan binary executable path could not be resolved"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_codeql_scan_reaches_subprocess_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();
    std::fs::write(repo.join("package.json"), "{}\n").unwrap();
    std::fs::write(repo.join("server.js"), "db.query(req.query.q)\n").unwrap();
    fake_codeql_binary(&fake_bin);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_bin.display(), old_path.to_string_lossy());
    let output = kuzushi_command(&home)
        .env("PATH", path)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("codeql:scan")
        .arg("--input")
        .arg(r#"{"language":"javascript"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("js/sql-injection")
    );
    assert!(body
        .pointer("/data/persisted/findingsDb")
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(".kuzushi/v3/index.sqlite3")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
    assert_latest_static_artifacts(&repo, "codeql");
    let run_id = latest_run_id(&repo);
    let sarif_path = repo
        .join(".kuzushi/v3/runs")
        .join(&run_id)
        .join("report.sarif");
    let sarif = std::fs::read_to_string(sarif_path).unwrap();
    assert!(sarif.contains("2.1.0"), "sarif: {sarif}");
    assert!(sarif.contains("js/sql-injection"), "sarif: {sarif}");
    assert!(run_json(&repo, &run_id, "artifacts.json")
        .pointer("/artifacts")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .any(|artifact| artifact.pointer("/kind").and_then(Value::as_str) == Some("sarif")));
}

#[cfg(unix)]
#[test]
fn scan_tasks_codeql_reaches_scan_engine_path() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();
    std::fs::write(repo.join("package.json"), "{}\n").unwrap();
    std::fs::write(repo.join("server.js"), "db.query(req.query.q)\n").unwrap();
    fake_codeql_binary(&fake_bin);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_bin.display(), old_path.to_string_lossy());
    let output = kuzushi_command(&home)
        .env("PATH", path)
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("codeql")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));
    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "codeql");
}

#[test]
fn run_codeql_scan_missing_binary_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("codeql:scan")
        .arg("--input")
        .arg(format!(
            r#"{{"binary":"{}","language":"javascript"}}"#,
            temp.path().join("missing-codeql").display()
        ))
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("validated"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("codeql:scan binary executable path could not be resolved"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_recon_nmap_reaches_subprocess_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();
    fake_nmap_binary(&fake_bin);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_bin.display(), old_path.to_string_lossy());
    let output = kuzushi_command(&home)
        .env("PATH", path)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("recon:nmap")
        .arg("--input")
        .arg(r#"{"target":"192.0.2.10","ports":"80,443"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/hosts/0/address")
            .and_then(Value::as_str),
        Some("192.0.2.10")
    );
    assert_eq!(
        body.pointer("/data/services/1/port")
            .and_then(Value::as_u64),
        Some(443)
    );

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let mut store = ReconWorkspaceStore::open(&workspace).unwrap();
    let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
    let hosts = store.list_hosts(&workspace_id).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn run_recon_http_fingerprint_reaches_subprocess_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();
    fake_curl_binary(&fake_bin);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_bin.display(), old_path.to_string_lossy());
    let output = kuzushi_command(&home)
        .env("PATH", path)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("recon:http-fingerprint")
        .arg("--input")
        .arg(r#"{"target":"https://www.example.com"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/hosts/0/address")
            .and_then(Value::as_str),
        Some("www.example.com")
    );
    assert_eq!(
        body.pointer("/data/services/0/name")
            .and_then(Value::as_str),
        Some("https")
    );

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let mut store = ReconWorkspaceStore::open(&workspace).unwrap();
    let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
    let hosts = store.list_hosts(&workspace_id).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn run_recon_subdomain_reaches_subprocess_executor_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();
    fake_curl_binary(&fake_bin);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_bin.display(), old_path.to_string_lossy());
    let output = kuzushi_command(&home)
        .env("PATH", path)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("recon:subdomain")
        .arg("--input")
        .arg(r#"{"domain":"example.com","source":"crtsh"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/subdomains/0").and_then(Value::as_str),
        Some("api.example.com")
    );

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let mut store = ReconWorkspaceStore::open(&workspace).unwrap();
    let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
    assert_eq!(store.list_hosts(&workspace_id).unwrap().len(), 2);
}

#[test]
fn run_recon_http_fingerprint_missing_binary_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("recon:http-fingerprint")
        .arg("--input")
        .arg(format!(
            r#"{{"target":"https://www.example.com","binary":"{}"}}"#,
            temp.path().join("missing-curl").display()
        ))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("recon:http-fingerprint binary executable path could not be resolved"),
        "stderr: {stderr}"
    );
}

#[test]
fn run_findings_list_applies_filters_against_workspace_store() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    seed_findings(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("findings:list")
        .arg("--input")
        .arg(r#"{"severity":["high"],"verdict":["tp"],"name":"sql"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(body.pointer("/data/count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/data/findings/0/rule_id")
            .and_then(Value::as_str),
        Some("demo.sql")
    );
    assert!(body
        .get("output")
        .and_then(Value::as_str)
        .is_some_and(|output| output.contains("1 matching")));
}

#[test]
fn findings_command_uses_same_filter_core_as_run_tool() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    seed_findings(&repo);

    let output = kuzushi_command(&home)
        .arg("findings")
        .arg("--target")
        .arg(&repo)
        .arg("--severity")
        .arg("high")
        .arg("--verdict")
        .arg("tp")
        .arg("--name")
        .arg("sql")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/findings/0/rule_id").and_then(Value::as_str),
        Some("demo.sql")
    );
}

#[cfg(unix)]
#[test]
fn run_triage_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let finding = seed_untriaged_finding(&repo);
    let bridge = fake_triage_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("triage:run")
        .arg("--input")
        .arg(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/triaged").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(body.pointer("/data/tp").and_then(Value::as_u64), Some(1));
    assert!(body
        .get("output")
        .and_then(Value::as_str)
        .is_some_and(|output| output.contains("Triaged 1 of 1")));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
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

#[test]
fn run_triage_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    seed_untriaged_finding(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("triage:run")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
    assert_latest_failed_run_bundle(&repo, "triage:run", "requires an explicit model");
}

#[cfg(unix)]
#[test]
fn run_verify_finding_reaches_langgraph_runtime_bridge() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let finding = seed_triaged_finding(&repo);
    let bridge = fake_verify_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("verify:finding")
        .arg("--input")
        .arg(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/exploitable").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        body.pointer("/data/attackVector").and_then(Value::as_str),
        Some("curl POST /admin")
    );
    assert!(body
        .get("output")
        .and_then(Value::as_str)
        .is_some_and(|output| output.contains("VULNERABLE")));
}

#[test]
fn run_verify_finding_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let finding = seed_triaged_finding(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("verify:finding")
        .arg("--input")
        .arg(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
    assert_latest_failed_run_bundle(&repo, "verify:finding", "requires an explicit model");
}

#[cfg(unix)]
#[test]
fn run_patch_finding_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("src/db.ts"), "const query = req.query.q;\n").unwrap();
    init_git_repo(&repo);
    let finding = seed_triaged_finding(&repo);
    let bridge = fake_patch_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("patch:finding")
        .arg("--input")
        .arg(format!(
            r#"{{"fingerprint":"{}","maxIterations":1,"buildCmd":"true","testCmd":"true"}}"#,
            finding.fingerprint
        ))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/status").and_then(Value::as_str),
        Some("SOUND")
    );
    assert!(body
        .get("output")
        .and_then(Value::as_str)
        .is_some_and(
            |output| output.contains("patch:finding SOUND") && output.contains("--- a/src/db.ts")
        ));

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let patch_results = store
        .get_patch_results_for_finding(&finding.fingerprint)
        .unwrap();
    assert_eq!(patch_results.len(), 1);
    assert_eq!(patch_results[0].status.as_str(), "SOUND");
}

#[test]
fn run_patch_finding_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let finding = seed_triaged_finding(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("patch:finding")
        .arg("--input")
        .arg(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_threat_model_build_reaches_langgraph_runtime_bridge_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"express":"4"}}"#,
    )
    .unwrap();
    let bridge = fake_threat_model_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("threat-model:build")
        .arg("--input")
        .arg(r#"{"outputDir":".kuzushi/tm","methodology":"stride"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/document/methodology")
            .and_then(Value::as_str),
        Some("stride")
    );
    assert_eq!(
        body.pointer("/data/document/threats/0/id")
            .and_then(Value::as_str),
        Some("T-001")
    );
    assert!(kuzushi_core::capabilities::persistent_threat_model_path(&repo).exists());
    assert!(repo
        .join(".kuzushi/tm/normalized-threat-model.json")
        .exists());
}

#[test]
fn run_threat_model_read_loads_pasta_artifacts_without_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    let artifact_dir = repo.join(".kuzushi/v3/runs/run-1/threat-model-output");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        artifact_dir.join("pasta-s2.json"),
        r#"{"actors":[{"id":"actor-user","name":"User","type":"external-user"}],"services":[{"id":"web","name":"Web"}],"data_flows":[{"id":"flow-1","source":"actor-user","destination":"web","crosses":["tb-1"]}]}"#,
    )
    .unwrap();
    std::fs::write(
        artifact_dir.join("pasta-s3.json"),
        r#"{"trust_boundaries":[{"id":"tb-1","name":"edge","crossing_flow_ids":["flow-1"]}]}"#,
    )
    .unwrap();
    std::fs::write(
        artifact_dir.join("pasta-s4.json"),
        r#"{"threats":[{"id":"T-001","title":"Spoof login","stride_category":"spoofing","target_assets":["web"],"impact":"high","probability":0.8,"attack_scenario":"token theft"}]}"#,
    )
    .unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("threat-model:read")
        .arg("--input")
        .arg(r#"{"outputDir":".kuzushi/v3/runs/run-1/threat-model-output","methodology":"dread"}"#)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/document/threats/0/id")
            .and_then(Value::as_str),
        Some("T-001")
    );
    assert_eq!(
        body.pointer("/data/document/riskScores/methodology")
            .and_then(Value::as_str),
        Some("dread")
    );
}

#[test]
fn run_threat_model_build_without_model_degrades_deterministically() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("threat-model:build")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "partial results must be machine-readable and exit nonzero"
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body.get("status").and_then(Value::as_str), Some("partial"));
    assert_eq!(
        body.pointer("/data/provider").and_then(Value::as_str),
        Some("deterministic")
    );
}

#[test]
fn run_x_ray_read_loads_artifacts_without_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    write_x_ray_fixture(&repo);

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("x-ray:read")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/verdict/tier").and_then(Value::as_str),
        Some("READY")
    );
    assert_eq!(
        body.pointer("/data/entryPointCounts/total")
            .and_then(Value::as_u64),
        Some(2)
    );
}

#[cfg(unix)]
#[test]
fn run_x_ray_run_reaches_langgraph_runtime_bridge_and_writes_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("README.md"), "# app\n").unwrap();
    let bridge = fake_x_ray_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("x-ray:run")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.pointer("/data/runtimeMode").and_then(Value::as_str),
        Some("LangGraph")
    );
    assert_eq!(
        body.pointer("/data/verdict/tier").and_then(Value::as_str),
        Some("WATCH")
    );
    assert!(repo.join("x-ray/x-ray.md").exists());
    assert!(repo.join("x-ray/architecture.svg").exists());
}

#[test]
fn run_x_ray_run_without_model_fails_without_silent_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();

    let output = kuzushi_command(&home)
        .arg("--target")
        .arg(&repo)
        .arg("run")
        .arg("x-ray:run")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit model") && stderr.contains("fallback model"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn scan_triage_uses_same_registry_executor_path() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("main.tf"), "cidr_blocks = [\"0.0.0.0/0\"]\n").unwrap();
    let bridge = fake_triage_bridge(temp.path());

    let output = kuzushi_command(&home)
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("KUZUSHI_LANGGRAPH_BRIDGE", bridge.display().to_string())
        .arg("scan")
        .arg(&repo)
        .arg("--tasks")
        .arg("iac-scan")
        .arg("--triage")
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(body.get("findingsCount").and_then(Value::as_u64), Some(1));
    assert_eq!(
        body.pointer("/triage/triaged").and_then(Value::as_u64),
        Some(1)
    );

    let workspace = WorkspaceTarget::new(&repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::TruePositive)
    );
}

fn seed_untriaged_finding(repo: &std::path::Path) -> Finding {
    let workspace = WorkspaceTarget::new(repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        42,
        Some(42),
        Severity::High,
        "SQL injection in search",
    );
    store.insert_finding("run-1", &finding).unwrap();
    finding
}

fn seed_triaged_finding(repo: &std::path::Path) -> Finding {
    let workspace = WorkspaceTarget::new(repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        42,
        Some(42),
        Severity::High,
        "SQL injection in search",
    );
    let finding_id = store.insert_finding("run-1", &finding).unwrap();
    store
        .record_auto_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.9,
                rationale: "confirmed".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    finding
}

fn seed_taint_iris_next_mcp_artifacts(repo: &std::path::Path) {
    // The taint-iris-next MCP gate refuses to dispatch unless the joern CPG
    // (`.kuzushi/cpg.bin`) and CodeQL DB (`.kuzushi/codeql-db/`) artifacts
    // exist — the precondition `/planning` builds. The fake bridge does not
    // read them, so non-empty placeholders satisfy the gate.
    let kuzushi = repo.join(".kuzushi");
    std::fs::create_dir_all(kuzushi.join("codeql-db")).unwrap();
    std::fs::write(
        kuzushi.join("codeql-db").join("codeql-database.yml"),
        "primaryLanguage: javascript\n",
    )
    .unwrap();
    std::fs::write(kuzushi.join("cpg.bin"), "cpg-stub").unwrap();
}

#[cfg(unix)]
fn init_git_repo(repo: &std::path::Path) {
    for args in [
        vec!["init"],
        vec!["config", "user.email", "kuzushi@example.test"],
        vec!["config", "user.name", "Kuzushi Test"],
        // Keep the fixture repo hermetic against a host/global git config that
        // forces commit signing — tests must not depend on a signing key.
        vec!["config", "commit.gpgsign", "false"],
        vec!["config", "tag.gpgsign", "false"],
        vec!["add", "."],
        vec!["commit", "-m", "fixture"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn seed_findings(repo: &std::path::Path) {
    let workspace = WorkspaceTarget::new(repo).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let high = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        42,
        Some(42),
        Severity::High,
        "SQL injection in search",
    );
    let low = Finding::new_semgrep(
        "demo.token",
        "tests/token.ts",
        4,
        Some(4),
        Severity::Low,
        "Hardcoded token in tests",
    );
    let high_id = store.insert_finding("run-1", &high).unwrap();
    store.insert_finding("run-1", &low).unwrap();
    store
        .record_auto_triage(
            high_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.9,
                rationale: "confirmed".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
}
