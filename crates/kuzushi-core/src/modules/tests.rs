#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::{
        Finding, FindingListFilter, PatchStatus, Severity, StaticProofState, TriageOutcome,
        TriageVerdict,
    };
    use crate::runtime::{
        AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentToolLoopRequest,
        LoopHistoryEntry, TriageRequest,
    };
    use crate::workspace::WorkspaceTarget;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockRuntime {
        requests: Mutex<Vec<TriageRequest>>,
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                queries: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<TriageRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn queries(&self) -> Vec<AgentQueryRequest> {
            self.queries.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MockRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            let is_patch_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("security patch generator"));
            if is_patch_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "diff": "--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n",
                        "explanation": "sanitize query input before use"
                    })),
                    ..Default::default()
                });
            }
            let is_classifier_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("classifier gate"));
            if is_classifier_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "likely": false,
                        "score": 0.42,
                        "reason": "mock classifier score"
                    })),
                    ..Default::default()
                });
            }
            let is_agentic_sast_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("agentic SAST scanner"));
            if is_agentic_sast_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "ruleId": "agentic/sql-injection",
                            "filePath": "src/db.ts",
                            "startLine": 1,
                            "severity": "ERROR",
                            "message": "User input reaches SQL query",
                            "confidence": "HIGH",
                            "evidence": "Source: req.query.q -> sink: db.query"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_taint_cwe_select_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("Taint CWE selector"));
            if is_taint_cwe_select_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "cwes": [{
                            "id": "CWE-89",
                            "name": "SQL Injection",
                            "reason": "database query uses request input"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_taint_iris_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("IRIS-style taint analysis"));
            if is_taint_iris_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Request input reaches SQL query",
                            "cwe": "CWE-89",
                            "severity": "high",
                            "filePath": "src/db.ts",
                            "startLine": 1,
                            "message": "The request query is concatenated into a SQL query.",
                            "sourceSinkTrace": "req.query.q -> db.query",
                            "taintPath": [{
                                "filePath": "src/db.ts",
                                "line": 1,
                                "message": "source and sink",
                                "snippet": "db.query(req.query.q)"
                            }],
                            "confidence": "high",
                            "exploitPreconditions": "attacker controls q"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_taint_iris_next_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("Taint IRIS Next agent"));
            if is_taint_iris_next_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "selectedCwes": [{
                            "cwe": "CWE-89",
                            "reason": "raw query receives request data",
                            "catalogSignals": ["sink: query("],
                            "sourceSpec": "request query parameters",
                            "sinkSpec": "database query calls",
                            "sanitizerSpec": "parameterized query APIs",
                            "customCweRationale": ""
                        }],
                        "findings": [{
                            "title": "Request parameter reaches raw SQL query",
                            "cwe": "CWE-89",
                            "severity": "high",
                            "confidence": "medium",
                            "evidenceLevel": "linked",
                            "filePath": "src/routes.ts",
                            "startLine": 1,
                            "message": "The query uses request-controlled data in SQL construction.",
                            "sourceSinkTrace": "req.query.id -> db.query(sql)",
                            "catalogSignals": ["source: req.query", "sink: query("],
                            "customCweRationale": "",
                            "taintPath": [{
                                "filePath": "src/routes.ts",
                                "line": 1,
                                "message": "source and SQL sink",
                                "snippet": "db.query(req.query.id)"
                            }]
                        }],
                        "triage": [{
                            "status": "finding",
                            "cwe": "CWE-89",
                            "evidenceLevel": "linked",
                            "rationale": "request data reaches raw SQL query",
                            "filePath": "src/routes.ts",
                            "line": 1,
                            "catalogSignals": ["sink: query("]
                        }],
                        "notes": []
                    })),
                    ..Default::default()
                });
            }
            let is_carlini_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("Carlini Threat Hunt"));
            if is_carlini_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "ruleId": "carlini-threat-hunt/actor-xss",
                            "filePath": "src/app.ts",
                            "startLine": 9,
                            "severity": "ERROR",
                            "message": "Actor-controlled input reaches HTML response",
                            "confidence": "HIGH",
                            "evidence": "Source: request query -> sink: response HTML"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_systems_invariant_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query
                        .system_prompt
                        .contains("Systems Hunt invariant extractor")
                });
            if is_systems_invariant_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "invariants": [{
                            "id": "inv-1",
                            "surfaceId": "surface-1",
                            "kind": "length-buffer-coupling",
                            "summary": "packet length must fit the fixed buffer",
                            "statement": "length is checked before copy",
                            "rationale": "copy uses packet-controlled length",
                            "evidence": ["memcpy"],
                            "attackerControlledFields": ["len"],
                            "cheapVerifiable": true
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_systems_trigger_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query
                        .system_prompt
                        .contains("Systems Hunt trigger synthesizer")
                });
            if is_systems_trigger_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "triggers": [{
                            "id": "trig-1",
                            "surfaceId": "surface-1",
                            "orderedSteps": ["send oversized packet"],
                            "boundaryAssignments": {"len": "4096"},
                            "statePreconditions": ["connected"],
                            "attackerControlledFields": ["len"],
                            "expectedPrimitive": "stack overwrite",
                            "cheapVerifiable": true,
                            "rationale": "length reaches memcpy"
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_systems_hunt_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query
                        .system_prompt
                        .contains("Systems Hunt low-level vulnerability hunter")
                });
            if is_systems_hunt_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Oversized packet length reaches fixed buffer",
                            "cwe": "CWE-787",
                            "severity": "ERROR",
                            "filePath": "src/parser.c",
                            "startLine": 3,
                            "message": "packet length is copied into a 64-byte stack buffer",
                            "reasoning": "len comes from the packet header",
                            "triggerHypothesisIds": ["trig-1"],
                            "violatedInvariantIds": ["inv-1"],
                            "triggerSequence": ["send len=4096"],
                            "attackerControlledFields": ["len"],
                            "memoryPrimitive": "stack overwrite",
                            "cheapVerifiable": true
                        }]
                    })),
                    ..Default::default()
                });
            }
            let is_plugin_adapter_request =
                self.queries.lock().unwrap().last().is_some_and(|query| {
                    query.system_prompt.contains("pi-agent-core adapter")
                        || query.system_prompt.contains("Shinsa compliance adapter")
                        || query.system_prompt.contains("PromptArmor adapter")
                        || query
                            .system_prompt
                            .contains("vendor security assessment agent")
                });
            if is_plugin_adapter_request {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "summary": "mock adapter result",
                        "findings": [{
                            "ruleId": "adapter/mock-finding",
                            "filePath": "src/app.ts",
                            "startLine": 1,
                            "severity": "high",
                            "message": "Mock adapter finding grounded in source",
                            "evidence": "src/app.ts:1"
                        }],
                        "overallRisk": "medium",
                        "confidence": "medium"
                    })),
                    ..Default::default()
                });
            }
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(json!({
                    "fingerprint": "from-bridge",
                    "exploitable": true,
                    "poc_payload": "curl -X POST /admin",
                    "poc_description": "POST reaches the admin sink.",
                    "attack_vector": "curl POST /admin",
                    "preconditions": ["network access"],
                    "confidence": 0.82,
                    "proof_level": 3,
                    "proof_verdict": "exploited",
                })),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
            let verdict = if request.finding.rule_id.contains("fp") {
                TriageVerdict::FalsePositive
            } else {
                TriageVerdict::TruePositive
            };
            self.requests.lock().unwrap().push(request);
            Ok(TriageOutcome {
                verdict,
                confidence: 0.87,
                rationale: "mock pi-agent-core triage".to_string(),
                ..Default::default()
            })
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_blocking(
            &self,
            request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.queries.lock().unwrap().push(AgentQueryRequest::new(
                request.model.clone(),
                request.cwd.clone(),
                request.system_prompt.clone(),
                request.prompt.clone(),
            ));
            Ok(AgentLoopStep::Final {
                text: String::new(),
                structured: Some(json!({
                    "triggerable": true,
                    "rationale": "mock deep audit confirmed reachability",
                    "confidence": 0.88,
                    "evidence": [{
                        "file": "src/db.ts",
                        "start_line": 1,
                        "end_line": 1,
                        "note": "source reaches sink",
                        "kind": "sink"
                    }]
                })),
                cost_usd: Some(0.002),
            })
        }
    }

    #[cfg(unix)]
    fn fake_semgrep_binary(dir: &Path) -> PathBuf {
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
    fn fake_codeql_binary(dir: &Path) -> PathBuf {
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
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "message": { "text": "request query parameter" },
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "server.js" },
                          "region": { "startLine": 1 }
                        }
                      }
                    },
                    {
                      "message": { "text": "query reaches db.query" },
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "server.js" },
                          "region": { "startLine": 9 }
                        }
                      }
                    }
                  ]
                }
              ]
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
    fn fake_curl_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("curl-fixture.sh");
        fs::write(
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
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_nmap_binary(dir: &Path) -> PathBuf {
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

    fn write_carlini_threat_model_fixture(dir: &Path) {
        let state_dir = dir.join(".kuzushi");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            state_dir.join("threat-model.json"),
            r#"{
  "version": "2.0",
  "dfd": {
    "nodes": [
      {"id":"actor-user","type":"external-entity","name":"Authenticated User","description":"External authenticated user","trustZone":"external"},
      {"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}
    ],
    "flows": [
      {"id":"flow-1","sourceId":"actor-user","targetId":"web","description":"profile request","trustBoundaryIds":["tb-1"],"protocol":"https"}
    ],
    "trustBoundaries": [
      {"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}
    ]
  },
  "threats": [
    {"id":"T-001","actorIds":["actor-user"],"flowIds":["flow-1"],"targetElementIds":["web"],"category":"tampering","title":"Profile HTML injection","description":"query reaches HTML","attackVector":"crafted profile query","impact":"high","likelihood":"medium","affectedFiles":[{"filePath":"src/app.ts","startLine":9}]}
  ],
  "summary": {"total": 1, "bySeverity": {"high": 1}, "byCategory": {"tampering": 1}}
}
"#,
        )
        .unwrap();
    }

    fn write_systems_hunt_fixture(dir: &Path) {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
    }

    #[cfg(unix)]
    fn init_git_repo(dir: &Path) {
        for args in [
            vec!["init"],
            vec!["config", "user.email", "kuzushi@example.test"],
            vec!["config", "user.name", "Kuzushi Test"],
            vec!["add", "."],
            vec!["commit", "-m", "fixture"],
        ] {
            let output = Command::new("git")
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

    #[test]
    fn persist_full_mode_report_writes_findings_when_workspace_is_available() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };
        let report = crate::capabilities::full_mode_multi::FullModeReport {
            findings: vec![Finding::new_tool(
                "full-mode",
                "demo.rule",
                "src/main.rs",
                1,
                None,
                Severity::High,
                "demo finding",
            )],
            plan: crate::capabilities::full_mode_multi::FullModePlan {
                chunks: Vec::new(),
                total_files: 1,
                total_bytes: 10,
                total_tokens: 3,
            },
            chunks_dispatched: 1,
            chunks_failed: 0,
            cost_usd: 0.0,
            dry_run: false,
            first_chunk_error: None,
        };

        persist_full_mode_report(&ctx, &report).unwrap();

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let rows = store
            .list_findings_filtered(&FindingListFilter::default())
            .unwrap()
            .findings;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule_id, "demo.rule");
    }

    #[test]
    fn dispatches_vendor_assessment_artifacts_through_registry() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("soc2.md"),
            "SOC 2 controls cover access review.",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let runtime = MockRuntime::new();

        let attach = registry
            .execute_tool(
                "vendor-assessment:attach",
                json!({
                    "source": "soc2.md",
                    "vendorName": "Acme",
                    "productName": "Acme AI"
                }),
                &ctx,
            )
            .unwrap();
        assert_eq!(attach.get("ok").and_then(Value::as_bool), Some(true));
        assert!(workspace
            .root()
            .join(".kuzushi/vendor-assessment/scope.json")
            .exists());

        let prompts = registry
            .execute_tool(
                "vendor-assessment:prompts",
                json!({"runId": "prompt-fixture"}),
                &ctx,
            )
            .unwrap();
        assert_eq!(
            prompts
                .pointer("/data/prompts")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );

        let assessed = registry
            .execute_tool_with_runtime("vendor-assessment:assess", json!({}), &ctx, Some(&runtime))
            .unwrap();
        assert_eq!(assessed.get("ok").and_then(Value::as_bool), Some(true));
        let report_path = assessed
            .pointer("/data/artifacts/reportPath")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(report_path).exists());
        assert_eq!(
            assessed
                .pointer("/data/report/overallRisk")
                .and_then(Value::as_str),
            Some("medium")
        );
    }

    #[test]
    fn dispatches_chrome_rce_scan_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("services/mojo/broker")).unwrap();
        fs::write(
            temp.path().join("services/mojo/broker/handle.cc"),
            "void Broker(HANDLE h) {\n  ::DuplicateHandle(src, h, dst, &out, 0, false, 0);\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool("chrome-rce:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        let stored = store.list_findings(FindingListFilter::MAX_LIMIT).unwrap();
        assert!(stored.iter().any(|finding| finding.tool == "chrome-rce"));
    }

    #[test]
    fn chrome_rce_scan_rejects_non_directory_target() {
        let temp = tempdir().unwrap();
        let file_target = temp.path().join("handle.cc");
        fs::write(&file_target, "not a directory\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool(
                "chrome-rce:scan",
                json!({"target": file_target.display().to_string()}),
                &ctx,
            )
            .unwrap_err();

        assert!(err.to_string().contains("target is not a directory"));
    }

    #[test]
    fn chrome_rce_review_trigger_skips_without_diff_base() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool("chrome-rce:review-trigger", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(0)
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("skipped"));
    }

    #[test]
    fn chrome_rce_unknown_tool_errors_actionably() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = chrome_rce::execute_tool("chrome-rce:unknown", json!({}), &ctx).unwrap_err();

        assert!(err.to_string().contains("unknown chrome-rce tool"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_chrome_rce_review_trigger_with_git_diff() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "fixture\n").unwrap();
        init_git_repo(temp.path());
        fs::create_dir_all(temp.path().join("v8/src/maglev")).unwrap();
        fs::write(
            temp.path()
                .join("v8/src/maglev/maglev-phi-representation-selector.cc"),
            "// risky path\n",
        )
        .unwrap();
        let output = Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["commit", "-m", "hot path"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "chrome-rce:review-trigger",
                json!({"diffBase": "HEAD~1"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .or_else(|| result.pointer("/data/findings/0/ruleId"))
                .and_then(Value::as_str),
            Some("chrome-rce-hot-path-v8-maglev-phi-representation-selector")
        );
    }

    #[test]
    fn dispatches_plugin_backed_adapters_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "export const handler = (req: any) => req.query.name;\n",
        )
        .unwrap();
        let plugin_root = temp.path().join("plugin-root");
        fs::create_dir_all(&plugin_root).unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let runtime = MockRuntime::new();

        for tool in [
            "vuln-scout:audit",
            "tob:audit",
            "shinsa:quick-check",
            "prompt-armor:analyze",
        ] {
            let result = registry
                .execute_tool_with_runtime(
                    tool,
                    json!({"pluginRoot": plugin_root.display().to_string()}),
                    &ctx,
                    Some(&runtime),
                )
                .unwrap();
            assert_eq!(
                result.get("ok").and_then(Value::as_bool),
                Some(true),
                "{tool}"
            );
            assert!(
                result.pointer("/data/findings/0").is_some()
                    || result.pointer("/data/count").and_then(Value::as_u64) == Some(1),
                "{tool}"
            );
        }

        let stored = store.list_findings(FindingListFilter::MAX_LIMIT).unwrap();
        for tool in ["vuln-scout", "tob-audit", "shinsa", "prompt-armor"] {
            assert!(
                stored.iter().any(|finding| finding.tool == tool),
                "expected persisted finding from {tool}"
            );
        }
    }

    #[test]
    fn plugin_adapters_missing_dependency_fail_actionably() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };
        let runtime = MockRuntime::new();

        let err = registry
            .execute_tool_with_runtime("vuln-scout:audit", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();

        assert!(err.contains("@kuzushi/vuln-scout"));
        assert!(err.contains("pluginRoot"));
    }

    #[test]
    fn prompt_armor_network_tools_require_authorization() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("prompt-armor:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("authorized=true")));
    }

    #[test]
    fn prompt_armor_local_tools_manage_config_diff_and_report() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        fs::write(temp.path().join("run-a.txt"), "one\n").unwrap();
        fs::write(temp.path().join("run-b.txt"), "one\ntwo\n").unwrap();
        fs::create_dir_all(temp.path().join(".prompt-armor")).unwrap();
        fs::write(temp.path().join(".prompt-armor/scan.json"), "{}\n").unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let config_result = registry
            .execute_tool("prompt-armor:config", json!({"action": "init"}), &ctx)
            .unwrap();
        assert_eq!(
            config_result
                .pointer("/data/exists")
                .and_then(Value::as_bool),
            Some(true)
        );

        let diff_result = registry
            .execute_tool(
                "prompt-armor:diff",
                json!({"runA": "run-a.txt", "runB": "run-b.txt"}),
                &ctx,
            )
            .unwrap();
        assert_eq!(
            diff_result
                .pointer("/data/lineDelta")
                .and_then(Value::as_i64),
            Some(1)
        );

        let report_result = registry
            .execute_tool("prompt-armor:report", json!({}), &ctx)
            .unwrap();
        let report_path = report_result
            .pointer("/data/reportPath")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(report_path).exists());
        assert!(report_result
            .pointer("/data/artifacts")
            .and_then(Value::as_array)
            .is_some_and(|artifacts| !artifacts.is_empty()));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_recon_nmap_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        let binary = fake_nmap_binary(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "recon:nmap",
                json!({"target":"192.0.2.10","ports":"80,443","binary":binary.display().to_string()}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("192.0.2.10")
        );
        assert_eq!(
            result
                .pointer("/data/services/1/port")
                .and_then(Value::as_u64),
            Some(443)
        );
        let mut store = crate::recon::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        let hosts = store.list_hosts(&workspace_id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_recon_http_fingerprint_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        let binary = fake_curl_binary(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "recon:http-fingerprint",
                json!({"target":"https://www.example.com","binary":binary.display().to_string()}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            result
                .pointer("/data/services/0/name")
                .and_then(Value::as_str),
            Some("https")
        );
        let mut store = crate::recon::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        let hosts = store.list_hosts(&workspace_id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_recon_subdomain_through_registry_and_persists() {
        let temp = tempdir().unwrap();
        let binary = fake_curl_binary(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool(
                "recon:subdomain",
                json!({"domain":"example.com","source":"crtsh","binary":binary.display().to_string()}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/subdomains/0").and_then(Value::as_str),
            Some("api.example.com")
        );
        let mut store = crate::recon::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        assert_eq!(store.list_hosts(&workspace_id).unwrap().len(), 2);
    }

    #[test]
    fn recon_missing_workspace_failure_is_explicit() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let error = registry
            .execute_tool(
                "recon:http-fingerprint",
                json!({"target":"example.com"}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("active workspace"));
    }

    #[test]
    fn dispatches_catalog_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let result = registry
            .execute_tool("catalog:modules", Value::Null, &ctx)
            .unwrap();
        assert!(result.as_array().unwrap().iter().any(|catalog_entry| {
            catalog_entry.get("id").and_then(Value::as_str) == Some("semgrep")
        }));
        assert!(!result.as_array().unwrap().iter().any(|catalog_entry| {
            catalog_entry.get("id").and_then(Value::as_str) == Some("context-lite")
        }));
    }

    #[test]
    fn dispatches_context_build_snapshot() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        fs::create_dir(temp.path().join("node_modules")).unwrap();
        fs::write(temp.path().join("node_modules/skip.js"), "skip\n").unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("context:build", json!({"sampleLimit": 10}), &ctx)
            .unwrap();
        let sample = result
            .pointer("/data/snapshot/filesSample")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/totalFiles")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            result
                .pointer("/data/snapshot/repoContext/languages/0")
                .and_then(Value::as_str),
            Some("Rust")
        );
        assert!(sample.contains(&"Cargo.toml"));
        assert!(sample.contains(&"src/lib.rs"));
        assert!(!sample.contains(&"node_modules/skip.js"));
        let snapshot_path = result
            .pointer("/data/snapshotPath")
            .and_then(Value::as_str)
            .unwrap();
        let persisted = fs::read_to_string(snapshot_path).unwrap();
        let persisted: Value = serde_json::from_str(&persisted).unwrap();
        assert_eq!(
            persisted.get("target").and_then(Value::as_str),
            Some(workspace.root().to_str().unwrap())
        );
        assert_eq!(
            persisted
                .pointer("/fileIndex/totalFiles")
                .and_then(Value::as_u64),
            Some(2)
        );
    }

    #[test]
    fn dispatches_hidden_context_lite_index_without_listing_it_as_visible_tool() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("server.ts"), "export const ok = true;\n").unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        assert!(registry.resolve_tool("context-lite:index").is_none());
        let result = registry
            .execute_tool("context-lite:index", json!({"sampleLimit": 5}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/snapshot/repoContext/languages/0")
                .and_then(Value::as_str),
            Some("TypeScript")
        );
    }

    #[test]
    fn context_build_enrichment_request_fails_explicitly() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool("context:build", json!({"enrichment": true}), &ctx)
            .unwrap_err()
            .to_string();

        assert!(err.contains("does not support LLM enrichment yet"));
        assert!(err.contains(r#""enrichment":false"#));
    }

    // ----- TriageOutcome cost field round-trips through persistence

    #[test]
    fn triage_outcome_persists_cost_usd() {
        use crate::findings::FindingStore;
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-cost-test", std::path::Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool("test", "rule", "src/x.c", 1, None, Severity::High, "msg");
        let finding_id = store.insert_finding("run-cost-test", &finding).unwrap();

        let outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "test".to_string(),
            cost_usd: 0.0123,
        };
        store.save_triage(finding_id, &outcome).unwrap();

        // Reload the finding via the public API and confirm the
        // verdict + confidence round-trip; cost_usd persists in the
        // triage table even if Finding.triage doesn't surface it.
        let reloaded = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert!(reloaded.triage.is_some());
        let triage = reloaded.triage.unwrap();
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
        assert!((triage.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn triage_outcome_default_cost_is_zero() {
        let o = TriageOutcome::default();
        assert_eq!(o.cost_usd, 0.0);
        assert_eq!(o.verdict, TriageVerdict::NeedsReview);
    }

    #[test]
    fn dispatches_dep_hygiene_check() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest","react":"^18.2.0"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("dep-hygiene:check", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/packageName")
                .and_then(Value::as_str),
            Some("lodash")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("dep-hygiene: 1 risky specifier")));
    }

    #[test]
    fn dep_hygiene_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "dep-hygiene:check",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("dep-hygiene: target does not exist"));
    }

    #[test]
    fn dispatches_secret_scan() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("secret-scan:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findings/0/ruleId")
                .and_then(Value::as_str),
            Some("secret-scan/openai-api-key")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("secret-scan: 1 finding")));
    }

    #[test]
    fn secret_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "secret-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("secret-scan: target is not a directory"));
    }

    #[test]
    fn dispatches_iac_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Dockerfile"),
            "FROM node:latest\nUSER root\n",
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool("iac-scan:scan", json!({"kind": "dockerfile"}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/ruleId")
                .and_then(Value::as_str),
            Some("iac-scan/dockerfile-floating-image")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 3);
    }

    #[test]
    fn iac_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "iac-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("iac-scan: target does not exist"));
    }

    #[test]
    fn dispatches_sast_scan_through_scan_runner_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene", "secret-scan"],
                    "severity": ["high"]
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(store.list_findings(10).unwrap().len(), 2);
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| {
                output.contains("sast:scan")
                    && output.contains("dep-hygiene")
                    && output.contains("secret-scan")
            }));
    }

    #[test]
    fn sast_scan_can_continue_into_pi_agent_core_triage() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene"],
                    "triage": true
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/triage/triaged")
                .and_then(Value::as_u64),
            Some(1)
        );
        let stored = store.list_findings(10).unwrap();
        assert_eq!(
            stored[0].triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
        assert_eq!(runtime.requests().len(), 1);
    }

    #[test]
    fn dispatches_agentic_sast_scan_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "agentic-sast:scan",
                json!({"maxFindings": 5, "severity": ["ERROR"]}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("agentic/sql-injection")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        let query = runtime.queries().pop().unwrap();
        assert_eq!(query.model, "openai:gpt-4.1");
        assert!(query.prompt.contains("src/db.ts"));
        assert!(query.prompt.contains("db.query(req.query.q)"));
    }

    #[test]
    fn whitebox_agent_tools_for_agentic_sast_are_read_only() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/mode").and_then(Value::as_str),
            Some("whitebox-static")
        );
        let query = runtime.queries().pop().unwrap();
        assert_eq!(query.tool_policy.profile, "whitebox-static");
        assert_eq!(
            query.tool_policy.tools,
            vec![
                "Read".to_string(),
                "Glob".to_string(),
                "Grep".to_string(),
                "LS".to_string()
            ]
        );
        for forbidden in ["Bash", "shell", "Write", "Edit", "patch", "apply_patch"] {
            assert!(
                !query
                    .tool_policy
                    .tools
                    .iter()
                    .any(|tool| tool.eq_ignore_ascii_case(forbidden)),
                "forbidden whitebox tool was enabled: {forbidden}"
            );
        }
    }

    #[test]
    fn whitebox_triage_prompt_for_agentic_sast_uses_static_schema() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        let query = runtime.queries().pop().unwrap();
        assert!(query.system_prompt.contains("whitebox-static mode"));
        for field in [
            "\"verdict\"",
            "\"staticProofState\"",
            "\"source\"",
            "\"sink\"",
            "\"path\"",
            "\"sanitizerAssessment\"",
            "\"guardAssessment\"",
            "\"citations\"",
            "\"assumptions\"",
            "\"missingEvidence\"",
            "\"triggerNarrative\"",
            "\"impactNarrative\"",
            "\"recommendedFix\"",
        ] {
            assert!(query.system_prompt.contains(field), "missing {field}");
        }
        for rule in [
            "Do not include payloads",
            "PoCs",
            "exploit execution",
            "runtime exploitability claims",
            "no active exploitation",
            "no HTTP replay",
            "no fuzzing",
            "no live target scanning",
            "no PoC generation",
            "no PoC execution",
        ] {
            assert!(
                query.system_prompt.contains(rule) || query.prompt.contains(rule),
                "whitebox prompt did not include rule {rule}"
            );
        }
        assert!(query
            .prompt
            .contains("Every reported claim must cite repository source lines"));
    }

    #[test]
    fn agentic_sast_scan_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("agentic-sast:scan", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("agentic-sast:scan", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn dispatches_taint_iris_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "taint-iris:hunt",
                json!({
                    "maxFindings": 5,
                    "TAINT_IRIS_PROMPT": "Focus on SQL sinks only."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/cwes/0/id").and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("taint-iris/cwe-89")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "taint-iris");
        assert!(stored[0].message.contains("req.query.q -> db.query"));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 2);
        assert!(queries[0].system_prompt.contains("Taint CWE selector"));
        assert!(queries[1]
            .system_prompt
            .contains("IRIS-style taint analysis"));
        assert!(queries[1].prompt.contains("Focus on SQL sinks only."));
        assert!(queries[1].prompt.contains("CWE-89"));
    }

    #[test]
    fn taint_iris_hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("taint-iris:hunt", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("taint-iris:hunt", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn dispatches_hidden_taint_cwe_selector_through_runtime_without_listing_it_as_visible_tool() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        assert!(registry.resolve_tool("pipeline:taint-cwe-select").is_none());

        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime("pipeline:taint-cwe-select", json!({}), &ctx, Some(&runtime))
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/cwes/0/id").and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(runtime.queries().len(), 1);
    }

    #[test]
    fn dispatches_carlini_threat_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "res.send(`<p>${req.query.name}</p>`)\n",
        )
        .unwrap();
        write_carlini_threat_model_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "carlini-threat-hunt:run",
                json!({"maxActors": 1, "runsPerActor": 1}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("carlini-threat-hunt/actor-xss")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/actor_fingerprint")
                .and_then(Value::as_str),
            Some("carlini-threat-hunt:Authenticated_User:0")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "carlini-threat-hunt");
        assert_eq!(
            stored[0].actor_fingerprint.as_deref(),
            Some("carlini-threat-hunt:Authenticated_User:0")
        );
        let query = runtime.queries().pop().unwrap();
        assert_eq!(query.model, "openai:gpt-4.1");
        assert!(query.prompt.contains("Authenticated User"));
        assert!(query.prompt.contains("src/app.ts"));
    }

    #[test]
    fn carlini_threat_hunt_requires_threat_model_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("carlini-threat-hunt:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an existing .kuzushi/threat-model.json"));

        write_carlini_threat_model_fixture(temp.path());
        let err = registry
            .execute_tool("carlini-threat-hunt:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("carlini-threat-hunt:run", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn sast_scan_routes_agentic_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("agentic")
        );
        assert!(result
            .pointer("/data/agentic/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "agentic");
    }

    #[test]
    fn sast_scan_routes_carlini_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "res.send(`<p>${req.query.name}</p>`)\n",
        )
        .unwrap();
        write_carlini_threat_model_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["carlini-threat-hunt"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("carlini-threat-hunt")
        );
        assert!(result
            .pointer("/data/carliniThreatHunt/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(
            store.list_findings(10).unwrap()[0].tool,
            "carlini-threat-hunt"
        );
    }

    #[test]
    fn sast_scan_routes_taint_iris_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["taint-iris"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("taint-iris")
        );
        assert!(result
            .pointer("/data/taintIris/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "taint-iris");
    }

    #[test]
    fn sast_scan_routes_taint_iris_next_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["taint-iris-next"],
                    "maxCatalogEntries": 3,
                    "maxAgentFindings": 5,
                    "minEvidenceLevel": "candidate"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("taint-iris-next")
        );
        assert!(result
            .pointer("/data/taintIrisNext/count")
            .and_then(Value::as_u64)
            .is_some());
        assert!(result
            .pointer("/data/runIds/taintIrisNext")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "taint-iris-next");
    }

    #[test]
    fn dispatches_systems_hunt_through_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        write_systems_hunt_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "systems-hunt:systems-hunt",
                json!({"maxFindings": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("systems-hunt/cwe-787")
        );
        assert!(result
            .pointer("/data/artifacts/0")
            .and_then(Value::as_str)
            .is_some_and(|path| path.starts_with(".kuzushi/systems-hunt/")));
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "systems-hunt");
    }

    #[test]
    fn systems_hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        write_systems_hunt_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool("systems-hunt:systems-hunt", json!({"maxFindings": 5}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "systems-hunt:systems-hunt",
                json!({"maxFindings": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn sast_scan_routes_systems_hunt_task_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        write_systems_hunt_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["systems-hunt"],
                    "maxFindings": 5
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findingsCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result.pointer("/data/engines/0").and_then(Value::as_str),
            Some("systems-hunt")
        );
        assert!(result
            .pointer("/data/systemsHunt/count")
            .and_then(Value::as_u64)
            .is_some());
        assert!(result
            .pointer("/data/runIds/systemsHunt")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "systems-hunt");
    }

    #[test]
    fn sast_scan_runs_verify_patch_and_writes_run_artifacts() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/db.ts"),
            "const query = req.query.q;\n",
        )
        .unwrap();
        init_git_repo(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["agentic"],
                    "verify": true,
                    "autoPatch": true,
                    "maxIterations": 1,
                    "buildCmd": "true",
                    "testCmd": "true"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/triage/triaged")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/verification/verified")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/patch/patched")
                .and_then(Value::as_u64),
            Some(1)
        );

        let summary = result
            .pointer("/data/artifacts/summary")
            .and_then(Value::as_str)
            .unwrap();
        let triage_log = result
            .pointer("/data/artifacts/triageJsonl")
            .and_then(Value::as_str)
            .unwrap();
        let verify_log = result
            .pointer("/data/artifacts/verifyJsonl")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(summary).exists());
        assert!(fs::read_to_string(summary)
            .unwrap()
            .contains("\"verification\""));
        assert!(fs::read_to_string(triage_log)
            .unwrap()
            .contains("triage:complete"));
        let verify_log = fs::read_to_string(verify_log).unwrap();
        assert!(verify_log.contains("verification:complete"));
        assert!(verify_log.contains("patch:complete"));

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let patch_results = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(patch_results.len(), 1);
        assert_eq!(patch_results[0].status, PatchStatus::Sound);
    }

    #[test]
    fn whitebox_static_sast_mode_disables_execution_and_patch_paths() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene"],
                    "verify": true,
                    "autoPatch": true,
                    "pocHarness": true,
                    "pocExecution": true,
                    "dynamicAnalysis": true,
                    "cryptoBehavioralTesting": true,
                    "proofState": "execution_confirmed"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/mode").and_then(Value::as_str),
            Some("whitebox-static")
        );
        assert_eq!(
            result
                .pointer("/data/whiteboxStatic/enabled")
                .and_then(Value::as_bool),
            Some(true)
        );
        for pointer in [
            "/data/whiteboxStatic/verify",
            "/data/whiteboxStatic/pocHarness",
            "/data/whiteboxStatic/pocExecution",
            "/data/whiteboxStatic/dynamicAnalysis",
            "/data/whiteboxStatic/cryptoBehavioralTesting",
            "/data/whiteboxStatic/patching",
            "/data/whiteboxStatic/autoPatch",
            "/data/whiteboxStatic/executionProofStates",
            "/data/whiteboxStatic/runtimeExploitabilityClaims",
        ] {
            assert_eq!(
                result.pointer(pointer).and_then(Value::as_bool),
                Some(false)
            );
        }
        assert_eq!(
            result
                .pointer("/data/verification/verified")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            result
                .pointer("/data/patch/patched")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert!(runtime.requests().is_empty());
        assert!(runtime.queries().is_empty());

        let scan_input = fs::read_to_string(
            result
                .pointer("/data/artifacts/dir")
                .and_then(Value::as_str)
                .map(Path::new)
                .unwrap()
                .join("scan-input.json"),
        )
        .unwrap();
        assert!(scan_input.contains("\"mode\": \"whitebox-static\""));
        assert!(!scan_input.contains("execution_confirmed"));
        assert!(scan_input.contains("needs_runtime_evidence"));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("Static narrative: trigger path summarized"));
        assert!(result
            .pointer("/data/staticNarratives/count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0));
        let static_narratives = fs::read_to_string(
            result
                .pointer("/data/artifacts/staticNarratives")
                .and_then(Value::as_str)
                .unwrap(),
        )
        .unwrap();
        assert!(static_narratives.contains("Static trigger path"));
        assert!(static_narratives.contains("Potential impact"));
        assert!(static_narratives.contains("Evidence limits"));
        assert!(!static_narratives
            .to_ascii_lowercase()
            .contains("confirmed exploit"));
        assert!(!static_narratives
            .to_ascii_lowercase()
            .contains("poc payload"));

        let stored = store.list_findings(10).unwrap();
        assert!(!stored.is_empty());
        assert!(stored
            .iter()
            .all(|finding| { finding.static_proof_state == Some(StaticProofState::SignalOnly) }));
    }

    #[cfg(unix)]
    #[test]
    fn whitebox_diff_sast_mode_writes_pr_scope_artifact() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        init_git_repo(temp.path());
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest","express":"latest"}}"#,
        )
        .unwrap();
        for args in [vec!["add", "."], vec!["commit", "-m", "pr"]] {
            let output = Command::new("git")
                .args(args)
                .current_dir(temp.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "sast:scan",
                json!({
                    "mode": "whitebox-static",
                    "taskMode": "manual",
                    "tasks": ["dep-hygiene"],
                    "diffBase": "HEAD~1"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result.pointer("/data/mode").and_then(Value::as_str),
            Some("whitebox-static")
        );
        assert_eq!(
            result
                .pointer("/data/whiteboxDiff/noRemoteProviderRequired")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result
                .pointer("/data/whiteboxDiff/summary/changedFiles")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert!(result
            .pointer("/data/whiteboxDiff/findingTags")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty()));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("Diff scope: 1 changed file"));
        let artifact = result
            .pointer("/data/artifacts/whiteboxDiff")
            .and_then(Value::as_str)
            .unwrap();
        let artifact_body = fs::read_to_string(artifact).unwrap();
        assert!(artifact_body.contains("\"changedFiles\""));
        assert!(artifact_body.contains("\"noRemoteProviderRequired\": true"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_semgrep_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("server.js"), "res.send(req.query.x)\n").unwrap();
        let binary = fake_semgrep_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({"binary": binary.display().to_string(), "config": "p/security-audit"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("javascript.express.security.audit.xss")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn semgrep_static_evidence_direct_tool_indexes_whitebox_signal_only() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("server.js"),
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/x', (req, res) => {",
                "  const name = req.query.name;",
                "  const prefix = '<h1>';",
                "  const suffix = '</h1>';",
                "  const body = prefix + name;",
                "  const html = body + suffix;",
                "  res.status(200);",
                "  res.set('content-type', 'text/html');",
                "  res.send(html);",
            ]
            .join("\n"),
        )
        .unwrap();
        let binary = fake_semgrep_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({
                    "binary": binary.display().to_string(),
                    "mode": "whitebox-static"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/findings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(
            result
                .pointer("/data/persisted/staticEvidence/findingsIndexed")
                .and_then(Value::as_u64),
            Some(1)
        );

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(&workspace).unwrap();
        let nodes = evidence_store
            .list_nodes_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|node| {
            node.kind == crate::static_evidence::StaticEvidenceNodeKind::ScannerSignal
                && node
                    .metadata
                    .pointer("/truePositiveByDefault")
                    .and_then(Value::as_bool)
                    == Some(false)
        }));
    }

    #[test]
    fn semgrep_missing_binary_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "semgrep:scan",
                json!({"binary": temp.path().join("missing-semgrep").display().to_string()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("semgrep: could not find scanner binary"));
        assert!(err.contains("Install Semgrep"));
        assert!(err.contains(r#""binary":"/path/to/semgrep""#));
        assert!(err.contains("Next: run semgrep:scan"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_codeql_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("package.json"), "{}\n").unwrap();
        fs::write(temp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({"binary": binary.display().to_string(), "language": "javascript"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("js/sql-injection")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn codeql_static_evidence_direct_tool_indexes_whitebox_code_flow() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("package.json"), "{}\n").unwrap();
        fs::write(
            temp.path().join("server.js"),
            [
                "const q = req.query.q;",
                "function load(db) {",
                "  const prefix = 'select ';",
                "  const table = 'users';",
                "  const where = ' where name = ';",
                "  const sql = prefix + '* from ' + table + where;",
                "  const suffix = q;",
                "  const built = sql + suffix;",
                "  return db.query(built);",
            ]
            .join("\n"),
        )
        .unwrap();
        let binary = fake_codeql_binary(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({
                    "binary": binary.display().to_string(),
                    "language": "javascript",
                    "mode": "whitebox-static"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/findings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(
            result
                .pointer("/data/persisted/staticEvidence/findingsIndexed")
                .and_then(Value::as_u64),
            Some(1)
        );

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(&workspace).unwrap();
        let nodes = evidence_store
            .list_nodes_for_finding(&finding.fingerprint)
            .unwrap();
        assert!(nodes.iter().any(|node| {
            node.kind == crate::static_evidence::StaticEvidenceNodeKind::ScannerSignal
                && node
                    .metadata
                    .pointer("/truePositiveByDefault")
                    .and_then(Value::as_bool)
                    == Some(false)
        }));
        assert!(nodes
            .iter()
            .any(|node| node.kind == crate::static_evidence::StaticEvidenceNodeKind::DataflowStep));
    }

    #[test]
    fn codeql_missing_binary_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let err = registry
            .execute_tool(
                "codeql:scan",
                json!({
                    "binary": temp.path().join("missing-codeql").display().to_string(),
                    "language": "javascript"
                }),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("codeql: could not find CodeQL CLI"));
        assert!(err.contains("github/codeql-cli-binaries"));
        assert!(err.contains(r#""binary":"/path/to/codeql""#));
        assert!(err.contains("Next: run codeql:scan"));
    }

    #[test]
    fn dispatches_findings_list_with_filters() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let confirmed = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let low = Finding::new_semgrep(
            "demo.token",
            "tests/token.ts",
            3,
            Some(3),
            Severity::Low,
            "Hardcoded token in tests",
        );
        let confirmed_id = store.insert_finding("run-1", &confirmed).unwrap();
        store.insert_finding("run-1", &low).unwrap();
        store
            .save_triage(
                confirmed_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed path".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let result = registry
            .execute_tool(
                "findings:list",
                json!({"severity": ["high"], "verdict": ["tp"], "name": "sql"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("demo.sql")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("SQL injection in search")));
    }

    #[test]
    fn dispatches_triage_run_with_runtime_and_persists_outcomes() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let confirmed = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let ignored = Finding::new_semgrep(
            "demo.fp",
            "src/debug.ts",
            2,
            Some(2),
            Severity::Low,
            "Debug log flagged",
        );
        store.insert_finding("run-1", &confirmed).unwrap();
        store.insert_finding("run-1", &ignored).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "triage:run",
                json!({
                    "fingerprint": confirmed.fingerprint.clone(),
                    "TRIAGE_PROMPT": "Use repository evidence only."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/triaged").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(result.pointer("/data/tp").and_then(Value::as_u64), Some(1));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Triaged 1 of 1")));

        let stored = store
            .get_finding_by_fingerprint(&confirmed.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
        let requests = runtime.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, "openai:gpt-4.1");
        assert_eq!(
            requests[0].prompt_template.as_deref(),
            Some("Use repository evidence only.")
        );
    }

    #[test]
    fn triage_run_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let err = registry
            .execute_tool("triage:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime("triage:run", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn triage_run_reports_no_matching_findings_without_calling_runtime() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "triage:run",
                json!({"fingerprint": "missing"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            result.pointer("/data/triaged").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            result
                .pointer("/data/missingFingerprints/0")
                .and_then(Value::as_str),
            Some("missing")
        );
        assert!(runtime.requests().is_empty());
    }

    #[test]
    fn dispatches_classifier_gate_score_and_persists_skip_triage() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "classifier-gate:score",
                json!({
                    "findingFingerprint": finding.fingerprint.clone(),
                    "targetPercentile": 0.9
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        let score = result
            .pointer("/data/score")
            .and_then(Value::as_f64)
            .unwrap();
        assert!((score - 0.42).abs() < 0.000_001);
        assert_eq!(
            result
                .pointer("/data/shouldDeepAudit")
                .and_then(Value::as_bool),
            Some(false)
        );
        let reloaded = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            reloaded.triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::NeedsReview)
        );
    }

    #[test]
    fn dispatches_deep_audit_through_runtime_and_persists_result() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
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
        store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "deep-audit:run",
                json!({
                    "findingFingerprint": finding.fingerprint.clone(),
                    "maxSteps": 1,
                    "depositUsd": 0.01
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/verdict").and_then(Value::as_str),
            Some("true_positive")
        );
        assert_eq!(
            result.pointer("/data/stepsUsed").and_then(Value::as_u64),
            Some(1)
        );
        let reloaded = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            reloaded.triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
    }

    #[test]
    fn full_mode_hunt_dry_run_plans_without_runtime() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, unsigned len) { char buf[64]; memcpy(buf, packet, len); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "full-mode:hunt",
                json!({
                    "dryRun": true,
                    "maxTokensPerChunk": 4096,
                    "depositUsdPerChunk": 0.5
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/dryRun").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result
                .pointer("/data/chunksDispatched")
                .and_then(Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn dispatches_verify_finding_through_runtime() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "verify:finding",
                json!({
                    "fingerprint": finding.fingerprint.clone(),
                    "VERIFY_PROMPT": "Prove exploitability with concrete runtime evidence."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/fingerprint").and_then(Value::as_str),
            Some("from-bridge")
        );
        assert_eq!(
            result.pointer("/data/exploitable").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result.pointer("/data/attackVector").and_then(Value::as_str),
            Some("curl POST /admin")
        );
        assert_eq!(
            result.pointer("/data/proofLevel").and_then(Value::as_u64),
            Some(3)
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("VULNERABLE")));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].model, "openai:gpt-4.1");
        assert!(queries[0]
            .prompt
            .contains("Prove exploitability with concrete runtime evidence."));
        assert!(queries[0].prompt.contains(&finding.fingerprint));
    }

    #[test]
    fn verify_finding_requires_triage_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "verify:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Run triage:run first")));

        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let err = registry
            .execute_tool(
                "verify:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "verify:finding",
                json!({"fingerprint": finding.fingerprint}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[cfg(unix)]
    #[test]
    fn dispatches_patch_finding_through_runtime_and_persists_result() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/db.ts"),
            "const query = req.query.q;\n",
        )
        .unwrap();
        init_git_repo(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
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
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool_with_runtime(
                "patch:finding",
                json!({
                    "fingerprint": finding.fingerprint.clone(),
                    "maxIterations": 1,
                    "buildCmd": "true",
                    "testCmd": "true"
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.get("ok").and_then(Value::as_bool),
            Some(true),
            "result: {result}"
        );
        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("SOUND")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("patch:finding SOUND")
                && output.contains("--- a/src/db.ts")));

        let patch_results = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(patch_results.len(), 1);
        assert_eq!(patch_results[0].status, PatchStatus::Sound);
        assert_eq!(patch_results[0].iterations, 1);

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].model, "openai:gpt-4.1");
        assert!(queries[0].prompt.contains(&finding.fingerprint));
        assert!(queries[0].prompt.contains("const query = req.query.q"));
    }

    #[test]
    fn patch_finding_requires_triage_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            9,
            Some(9),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let result = registry
            .execute_tool(
                "patch:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Run triage:run first")));

        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let err = registry
            .execute_tool(
                "patch:finding",
                json!({"fingerprint": finding.fingerprint.clone()}),
                &ctx,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "patch:finding",
                json!({"fingerprint": finding.fingerprint}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn dispatches_x_ray_read_artifact_parser() {
        let temp = tempdir().unwrap();
        let artifact_dir = temp.path().join("x-ray");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("x-ray.md"),
            "# X-Ray\n\n## X-Ray Verdict\nREADY\nReviewable surface.\n",
        )
        .unwrap();
        fs::write(
            artifact_dir.join("entry-points.md"),
            "# Entry Points\n\n> App | 2 entry points | 1 permissionless | 1 role-gated | 0 admin-only\n",
        )
        .unwrap();
        fs::write(
            artifact_dir.join("invariants.md"),
            "# Invariants\n\n### G-1 Balance\n### I-1 Oracle\n",
        )
        .unwrap();
        fs::write(
            artifact_dir.join("architecture.svg"),
            r#"<svg xmlns="http://www.w3.org/2000/svg" />"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let result = registry
            .execute_tool("x-ray:read", json!({}), &ctx)
            .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/verdict/tier").and_then(Value::as_str),
            Some("READY")
        );
        assert_eq!(
            result
                .pointer("/data/entryPointCounts/total")
                .and_then(Value::as_u64),
            Some(2)
        );
    }
}
