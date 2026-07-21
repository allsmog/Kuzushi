#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::{
        Finding, FindingListFilter, PatchStatus, Severity, StaticProofState, TriageOutcome,
        TriageVerdict,
    };
    use crate::run_artifacts::{run_dir, write_run_summary, RunSummary, TraceHandle};
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

    fn execute_authorized_tool(
        registry: &ModuleRegistry,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Value> {
        let prepared = registry
            .prepare_dispatch_input(name, input, ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
    }

    fn execute_authorized_tool_with_runtime(
        registry: &ModuleRegistry,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        let prepared = registry
            .prepare_dispatch_input(name, input, ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, ctx, runtime)
    }

    fn decoded_untrusted_records(
        prompt: &str,
        begin: &str,
        end: &str,
    ) -> Vec<crate::prompts::UntrustedRecord> {
        let mut records = Vec::new();
        let mut remaining = prompt;
        while let Some(start) = remaining.find(begin) {
            let frame = &remaining[start..];
            let frame_end = frame.find(end).unwrap() + end.len();
            records.push(crate::prompts::decode_untrusted_record(&frame[..frame_end]).unwrap());
            remaining = &frame[frame_end..];
        }
        records
    }

    struct MockRuntime {
        requests: Mutex<Vec<TriageRequest>>,
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    struct MutatingPatchRuntime {
        live_repo: PathBuf,
        observations: Mutex<Vec<(AgentQueryRequest, String)>>,
    }

    impl MutatingPatchRuntime {
        fn new(live_repo: PathBuf) -> Self {
            Self {
                live_repo,
                observations: Mutex::new(Vec::new()),
            }
        }

        fn observations(&self) -> Vec<(AgentQueryRequest, String)> {
            self.observations.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MutatingPatchRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let source = fs::read_to_string(request.cwd.join("src/db.ts"))?;
            fs::write(
                self.live_repo.join("src/db.ts"),
                "const query = concurrent_uncommitted_change;\n",
            )?;
            self.observations.lock().unwrap().push((request, source));
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(json!({
                    "diff": "--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n",
                    "explanation": "sanitize query input before use"
                })),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("mutating patch runtime only supports patch synthesis")
        }
    }

    struct FailingDeepAuditRuntime {
        chunk_runtime: MockRuntime,
    }

    impl FailingDeepAuditRuntime {
        fn new() -> Self {
            Self {
                chunk_runtime: MockRuntime::new(),
            }
        }
    }

    impl AgentRuntime for FailingDeepAuditRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.chunk_runtime.query_blocking(request)
        }

        fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
            self.chunk_runtime.triage_finding_blocking(request)
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            anyhow::bail!("simulated deep audit failure")
        }
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
            if let Some(structured) = self.exploit_chain_response() {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(structured),
                    ..Default::default()
                });
            }
            let is_full_mode_chunk = self
                .queries
                .lock()
                .unwrap()
                .last()
                .is_some_and(|query| query.system_prompt.contains("whole-codebase scanner"));
            if is_full_mode_chunk {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!([{
                        "file": "src/parser.c",
                        "line": 1,
                        "function": "parse",
                        "severity": "high",
                        "cwe": ["CWE-787"],
                        "title": "Packet length reaches fixed buffer",
                        "rationale": "packet-controlled length reaches memcpy without a bounds check"
                    }])),
                    ..Default::default()
                });
            }
            let is_patch_request = self
                .queries
                .lock()
                .unwrap()
                .last()
                .and_then(|query| query.structured_output.as_ref())
                .is_some_and(|output| output.name == "PatchSynthesis");
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
                .is_some_and(|query| query.prompt.starts_with("Taint IRIS Next\n"));
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
                    query.system_prompt.contains("LangGraph adapter")
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
                rationale: "mock LangGraph triage".to_string(),
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

    impl MockRuntime {
        fn exploit_chain_response(&self) -> Option<Value> {
            let queries = self.queries();
            let query = queries.last()?;
            if query.system_prompt.contains("exploit-chain code navigator") {
                return Some(json!({
                    "selections": [{
                        "filePath": "src/app.js",
                        "startLine": 1,
                        "endLine": 3,
                        "rationale": "request body reaches template rendering"
                    }]
                }));
            }
            query
                .system_prompt
                .contains("exploit-chain analyzer")
                .then(|| {
                    json!({
                        "evidence": [{
                            "kind": "template-rendering",
                            "filePath": "src/app.js",
                            "line": 2,
                            "snippet": "res.send(ejs.render(req.body.template));",
                            "rationale": "request body controls rendered template",
                            "confidence": 9
                        }],
                        "findings": [{
                            "ruleId": "exploit-chain/template-render",
                            "title": "Template render chain",
                            "severity": "high",
                            "filePath": "src/app.js",
                            "startLine": 2,
                            "message": "Request body controls template rendering.",
                            "evidenceIndexes": [0]
                        }]
                    })
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
PATH=/usr/bin:/bin
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

    fn javascript_fixture_with_line_9_sink() -> String {
        [
            "const q = req.query.q;",
            "function handler(req, res, db) {",
            "  const prefix = 'select ';",
            "  const table = 'users';",
            "  const where = ' where name = ';",
            "  const sql = prefix + '* from ' + table + where;",
            "  const suffix = q;",
            "  const built = sql + suffix;",
            "  return db.query(built);",
            "}",
            "res.send(req.query.name);",
        ]
        .join("\n")
            + "\n"
    }

    #[cfg(unix)]
    fn fake_codeql_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("codeql-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
PATH=/usr/bin:/bin
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
PATH=/usr/bin:/bin
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
PATH=/usr/bin:/bin
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
        let threat_model_path = crate::capabilities::persistent_threat_model_path(dir);
        fs::create_dir_all(threat_model_path.parent().unwrap()).unwrap();
        fs::write(
            threat_model_path,
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
            // Stay hermetic against a host git config that forces signing.
            vec!["config", "commit.gpgsign", "false"],
            vec!["config", "tag.gpgsign", "false"],
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

    fn seed_completed_detector_run(target: &Path, run_id: &str, tool_name: &str) {
        let record = crate::run_artifacts::ToolRunRecord::new(
            target, run_id, "tool", tool_name,
        );
        crate::run_artifacts::record_tool_run_started(
            record,
            &json!({"fixture": "detector input"}),
        );
        crate::run_artifacts::record_tool_run_complete(
            record,
            &json!({"ok": true, "output": "fixture detector completed"}),
        );
    }

    #[test]
    fn persist_full_mode_report_uses_the_canonical_trace_run_identity() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let trace = TraceHandle::jsonl(temp.path(), "run-full-mode-canonical");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };
        let mut report = crate::capabilities::full_mode_multi::FullModeReport {
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
            failed_chunk_errors: Vec::new(),
            cost_usd: Some(0.0),
            observed_cost_usd: 0.0,
            unresolved_provider_spend: false,
            dry_run: false,
            first_chunk_error: None,
        };

        persist_full_mode_report(&ctx, &mut report).unwrap();

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let rows = store
            .list_findings_filtered(&FindingListFilter::default())
            .unwrap()
            .findings;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule_id, "demo.rule");
        assert_eq!(rows[0].scan_id.as_deref(), Some("run-full-mode-canonical"));
        assert_eq!(report.findings[0].id, rows[0].id);
        assert_eq!(
            store
                .list_findings_for_scan_id("run-full-mode-canonical")
                .unwrap()
                .len(),
            1
        );
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("chrome-rce:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("chrome-rce:scan found")));
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("chrome-rce:review-trigger", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("skipped")
        );
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "hot path"])
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = MockRuntime::new();

        for tool in [
            "vuln-scout:audit",
            "tob:audit",
            "shinsa:quick-check",
            "prompt-armor:analyze",
        ] {
            let result = execute_authorized_tool_with_runtime(
                &registry,
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
            assert_eq!(
                result.get("status").and_then(Value::as_str),
                Some("completed"),
                "{tool}"
            );
            assert!(result
                .get("summary")
                .and_then(Value::as_str)
                .is_some_and(|summary| summary.starts_with(tool)));
            assert!(
                result.pointer("/data/findings/0").is_some()
                    || result.pointer("/data/count").and_then(Value::as_u64) == Some(1),
                "{tool}"
            );
        }

        let stored = store.list_findings(FindingListFilter::MAX_LIMIT).unwrap();
        assert_eq!(stored.len(), 1);
        let finding = &stored[0];
        assert_eq!(finding.corroboration_count, 4);
        let source_tools = finding
            .sources
            .iter()
            .map(|source| source.tool.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            source_tools,
            vec!["prompt-armor", "shinsa", "tob-audit", "vuln-scout"]
        );
        assert!(finding.sources.iter().all(|source| {
            !source.source_signature.is_empty()
                && !source.first_scan_id.is_empty()
                && !source.last_scan_id.is_empty()
                && !source.first_seen_at.is_empty()
                && !source.last_seen_at.is_empty()
        }));
    }

    #[test]
    fn plugin_adapters_missing_dependency_fail_actionably() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result =
            execute_authorized_tool(&registry, "prompt-armor:scan", json!({}), &ctx).unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert!(result
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| !errors.is_empty()));
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let config_result = execute_authorized_tool(
            &registry,
            "prompt-armor:config",
            json!({"action": "init"}),
            &ctx,
        )
        .unwrap();
        assert_completed_result_envelope(&config_result, "prompt-armor:config");
        assert_eq!(
            config_result
                .pointer("/data/exists")
                .and_then(Value::as_bool),
            Some(true)
        );

        let diff_result = execute_authorized_tool(
            &registry,
            "prompt-armor:diff",
            json!({"runA": "run-a.txt", "runB": "run-b.txt"}),
            &ctx,
        )
        .unwrap();
        assert_completed_result_envelope(&diff_result, "prompt-armor:diff complete");
        assert_eq!(
            diff_result
                .pointer("/data/lineDelta")
                .and_then(Value::as_i64),
            Some(1)
        );

        let report_result =
            execute_authorized_tool(&registry, "prompt-armor:report", json!({}), &ctx).unwrap();
        assert_eq!(
            report_result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(report_result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("prompt-armor:report complete")));
        assert!(report_result
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
        let report_path = report_result
            .pointer("/data/reportPath")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(report_path).exists());
        assert_eq!(
            report_result
                .pointer("/artifacts/0/path")
                .and_then(Value::as_str),
            Some(report_path)
        );
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = execute_authorized_tool(
            &registry,
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = execute_authorized_tool(
            &registry,
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = execute_authorized_tool(
            &registry,
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        assert_completed_result_envelope(&result, "context:build indexed");
        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/totalFiles")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/truncated")
                .and_then(Value::as_bool),
            Some(false)
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
    fn context_build_marks_file_index_truncation() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();
        fs::write(temp.path().join("c.rs"), "fn c() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("context:build", json!({"sampleLimit": 1}), &ctx)
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/totalFiles")
                .and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/truncated")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result
                .pointer("/data/snapshot/fileIndex/tree")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn context_build_projects_app_model_security_boundaries() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import express from 'express';\nconst app = express();\napp.use(csurf());\nconst tenantId = req.user.tenantId;\napp.post('/session', (req, res) => { req.session.user = req.body.user; res.cookie('sid', req.session.id); });\napp.post('/proxy', async (req, res) => fetch(req.body.url));\n",
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("context:build", json!({"sampleLimit": 10}), &ctx)
            .unwrap();
        let service_boundaries = result
            .pointer("/data/snapshot/appModel/serviceBoundaries")
            .and_then(Value::as_array)
            .unwrap();
        let outbound_clients = result
            .pointer("/data/snapshot/appModel/outboundClients")
            .and_then(Value::as_array)
            .unwrap();

        assert!(service_boundaries.iter().any(|boundary| {
            boundary.get("kind").and_then(Value::as_str) == Some("session_state_boundary")
        }));
        assert!(service_boundaries.iter().any(|boundary| {
            boundary.get("kind").and_then(Value::as_str) == Some("request_trust_boundary")
        }));
        assert!(service_boundaries.iter().any(|boundary| {
            boundary.get("kind").and_then(Value::as_str) == Some("tenant_isolation_boundary")
        }));
        assert!(outbound_clients.iter().any(|client| {
            client.get("kind").and_then(Value::as_str) == Some("external_service_client")
        }));
    }

    #[test]
    fn context_build_excludes_non_route_helper_calls_from_routes() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n[dependencies]\naxum = \"0.7\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import express from 'express';\nconst app = express();\napp.get('/users', handler);\nheaders.get('x-signature');\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use axum::{routing::get, Router};\nfn app() { Router::new().route(\"/ready\", get(ready)); builder.route(\"not-a-path\"); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("context:build", json!({"sampleLimit": 20}), &ctx)
            .unwrap();
        let app_routes = result
            .pointer("/data/snapshot/appModel/routes")
            .and_then(Value::as_array)
            .unwrap();
        let inventory_routes = result
            .pointer("/data/snapshot/repositoryInventory/routesControllers")
            .and_then(Value::as_array)
            .unwrap();

        assert_route_path(app_routes, "/users");
        assert_route_path(app_routes, "/ready");
        assert_no_route_path(app_routes, "x-signature");
        assert_no_route_path(app_routes, "not-a-path");
        assert_no_route_path(inventory_routes, "x-signature");
        assert_no_route_path(inventory_routes, "not-a-path");
    }

    #[test]
    fn context_build_projects_nextjs_route_methods_into_app_model() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/health")).unwrap();
        fs::create_dir_all(temp.path().join("pages/api/webhooks")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/health/route.ts"),
            "export function HEAD() { return new Response(null); }\nexport const OPTIONS = () => Response.json({ ok: true });\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("pages/api/webhooks/[[...slug]].ts"),
            "export default function handler(req, res) { res.json({ ok: true }); }\n",
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("context:build", json!({"sampleLimit": 20}), &ctx)
            .unwrap();
        let app_routes = result
            .pointer("/data/snapshot/appModel/routes")
            .and_then(Value::as_array)
            .unwrap();
        let inventory_routes = result
            .pointer("/data/snapshot/repositoryInventory/routesControllers")
            .and_then(Value::as_array)
            .unwrap();

        assert_route(app_routes, "HEAD", "/api/health", "Next.js");
        assert_route(app_routes, "OPTIONS", "/api/health", "Next.js");
        assert_route(app_routes, "ANY", "/api/webhooks/:slug", "Next.js");
        assert_route(inventory_routes, "HEAD", "/api/health", "Next.js");
        assert_route(inventory_routes, "OPTIONS", "/api/health", "Next.js");
        assert_route(inventory_routes, "ANY", "/api/webhooks/:slug", "Next.js");
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        assert!(registry
            .resolve_tool("context-lite:index")
            .is_some_and(|tool| tool.hidden));
        assert!(registry
            .tools()
            .all(|tool| tool.name != "context-lite:index"));
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            .record_run_started("run-cost-test", std::path::Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool("test", "rule", "src/x.c", 1, None, Severity::High, "msg");
        let finding_id = store.insert_finding("run-cost-test", &finding).unwrap();

        let outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "test".to_string(),
            cost_usd: 0.0123,
            cost_usd_exact: true,
        };
        store.record_auto_triage(finding_id, &outcome).unwrap();

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
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("dep-hygiene:check", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "dep-hygiene:");
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
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/tool")
                .and_then(Value::as_str),
            Some("dep-hygiene")
        );
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert!(result
            .pointer("/data/coreFindings/0/fingerprint")
            .and_then(Value::as_str)
            .is_some());
        assert!(result
            .pointer("/data/coreFindings/0/identityId")
            .and_then(Value::as_str)
            .is_some_and(|identity| identity.starts_with("fi_")));
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn dep_hygiene_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .execute_tool(
                "dep-hygiene:check",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("dep-hygiene:check target path"), "{detail}");
        assert!(
            detail.contains("could not be resolved inside workspace"),
            "{detail}"
        );
    }

    #[test]
    fn dispatches_cargo_audit_scan_without_lockfile() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("cargo-audit:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "cargo-audit:");
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(0)
        );
        assert!(result
            .pointer("/data/coreFindings")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert!(store.list_findings(10).unwrap().is_empty());
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
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("secret-scan:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "secret-scan:");
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
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/tool")
                .and_then(Value::as_str),
            Some("secret-scan")
        );
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert!(result
            .pointer("/data/coreFindings/0/fingerprint")
            .and_then(Value::as_str)
            .is_some());
        assert!(result
            .pointer("/data/coreFindings/0/identityId")
            .and_then(Value::as_str)
            .is_some_and(|identity| identity.starts_with("fi_")));
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn secret_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .execute_tool(
                "secret-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("secret-scan:scan target path"), "{detail}");
        assert!(
            detail.contains("could not be resolved inside workspace"),
            "{detail}"
        );
    }

    #[test]
    fn dispatches_license_scan_and_persists_findings() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"name":"demo","license":"AGPL-3.0"}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("LICENSE"),
            "GNU Affero General Public License\nVersion 3\n",
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("license-scan:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "license-scan:");
        assert_eq!(
            result.pointer("/data/count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/ruleId")
                .and_then(Value::as_str),
            Some("license-scan/strong-copyleft")
        );
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn license_scan_dispatch_honors_spdx_header_policy() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"name":"demo","license":"MIT"}"#,
        )
        .unwrap();
        fs::write(temp.path().join("LICENSE"), "MIT License\n").unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "license-scan:scan",
                json!({"requireSourceSpdxHeaders": true}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/findings/0/ruleId")
                .and_then(Value::as_str),
            Some("license-scan/missing-spdx-header")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/filePath")
                .and_then(Value::as_str),
            Some("src/lib.rs")
        );
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn license_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .execute_tool(
                "license-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("license-scan:scan target path"), "{detail}");
        assert!(
            detail.contains("could not be resolved inside workspace"),
            "{detail}"
        );
    }

    #[test]
    fn dispatches_sbom_scan_inventory() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("sbom-scan:scan", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "sbom-scan:");
        assert_eq!(
            result
                .pointer("/data/componentCount")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/components/0/name")
                .and_then(Value::as_str),
            Some("express")
        );
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("iac-scan:scan", json!({"kind": "dockerfile"}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "iac-scan:");
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
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(store.list_findings(10).unwrap().len(), 3);
    }

    #[test]
    fn iac_scan_missing_target_failure_is_explicit() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .execute_tool(
                "iac-scan:scan",
                json!({"target": temp.path().join("missing").display().to_string()}),
                &ctx,
            )
            .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("iac-scan:scan target path"), "{detail}");
        assert!(
            detail.contains("could not be resolved inside workspace"),
            "{detail}"
        );
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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

        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("sast:scan")));
        assert!(result
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
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
    fn sast_scan_explicit_cargo_audit_requires_lockfile() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .execute_tool(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["cargo-audit"]
                }),
                &ctx,
            )
            .unwrap_err();

        let detail = format!("{error:#}");
        assert!(detail.contains("explicitly requested"), "{detail}");
        assert!(detail.contains("cargo generate-lockfile"), "{detail}");
        assert!(store.list_findings(10).unwrap().is_empty());
    }

    #[test]
    fn exploit_chain_scan_honors_input_model_override() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.js"),
            "res.send(ejs.render(req.body.template));\n",
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config {
            model: Some("openai:gpt-config".to_string()),
            ..V2Config::default()
        };
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "exploit-chain:scan",
                json!({"model": "openai:gpt-input", "maxEvidence": 8}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        let queries = runtime.queries();
        assert_eq!(queries.len(), 2);
        assert!(queries
            .iter()
            .all(|query| query.model == "openai:gpt-input"));
    }

    #[test]
    fn sast_scan_can_continue_into_langgraph_runtime_triage() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let prompt_path = crate::options::prompt_override_path(workspace.root(), "sast", "triage");
        fs::create_dir_all(prompt_path.parent().unwrap()).unwrap();
        fs::write(&prompt_path, "Persistent triage guidance.").unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        let requests = runtime.requests();
        assert_eq!(requests.len(), 1);
        let prompt = requests[0].prompt_template.as_deref().unwrap();
        assert!(prompt.starts_with(crate::runtime::DEFAULT_TRIAGE_PROMPT));
        let record = crate::prompts::boundaries::decode_composed_target_prompt_context(
            crate::runtime::DEFAULT_TRIAGE_PROMPT,
            prompt,
        )
        .unwrap();
        assert_eq!(record.content, "Persistent triage guidance.");
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        assert_completed_result_envelope(&result, "agentic-sast:");
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        let queries = runtime.queries();
        let query = queries
            .iter()
            .find(|query| query.tool_policy.profile == "whitebox-static")
            .expect("expected a whitebox-static agent query");
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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

        let queries = runtime.queries();
        let query = queries
            .iter()
            .find(|query| query.tool_policy.profile == "whitebox-static")
            .expect("expected a whitebox-static agent query");
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
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let err = registry
            .execute_tool("agentic-sast:scan", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires") && err.contains("runtime"), "{err}");

        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "taint-iris:hunt",
                json!({
                    "maxFindings": 5,
                    "mcps": false,
                    "TAINT_IRIS_PROMPT": "Focus on SQL sinks only."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "taint-iris-next:");
        assert_eq!(
            result
                .pointer("/data/stats/totalFindings")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/selectedCwes/0/cwe")
                .and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("taint-iris-next/cwe-89")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "taint-iris-next");
        assert!(stored[0].message.contains("request-controlled data"));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].system_prompt, "Focus on SQL sinks only.");
        assert!(queries[0].prompt.contains("CWE-89"));
    }

    #[test]
    fn taint_iris_hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let err = registry
            .execute_tool("taint-iris:hunt", json!({ "mcps": false }), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires") && err.contains("runtime"), "{err}");

        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = MockRuntime::new();
        let err = registry
            .execute_tool_with_runtime(
                "taint-iris:hunt",
                json!({ "mcps": false }),
                &ctx,
                Some(&runtime),
            )
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
        assert!(registry.resolve_tool("pipeline:taint-cwe-select").is_some());
        assert!(!registry
            .tools()
            .any(|tool| tool.name == "pipeline:taint-cwe-select"));

        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime("pipeline:taint-cwe-select", json!({}), &ctx, Some(&runtime))
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
    fn dispatches_offense_review_threat_hunt_alias_through_runtime() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/app.ts"), "res.send(req.query.name)\n").unwrap();
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "offense-review:threat-hunt",
                json!({"maxActors": 1, "runsPerActor": 1}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "carlini-threat-hunt:");
        assert_eq!(runtime.queries().len(), 1);
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        assert!(err.contains("requires the LangGraph runtime"));

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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
    fn sast_scan_routes_offense_review_task_through_runtime_and_persists() {
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["offense-review"],
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
            Some("offense-review")
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "sast:scan",
                json!({
                    "taskMode": "manual",
                    "tasks": ["taint-iris"],
                    "mcps": false,
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
            Some("taint-iris-next")
        );
        assert!(result
            .pointer("/data/taintIrisNext/count")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(store.list_findings(10).unwrap()[0].tool, "taint-iris-next");
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
        // taint-iris-next:hunt now refuses to dispatch without the
        // CPG + CodeQL DB artifacts (the artifact-aware MCP probe
        // gates the policy). Stub both so the hunt phase routes.
        let kuzushi = temp.path().join(".kuzushi");
        fs::create_dir_all(&kuzushi).unwrap();
        fs::write(kuzushi.join("cpg.bin"), b"CPG\0stub").unwrap();
        let codeql_db = kuzushi.join("codeql-db");
        fs::create_dir_all(&codeql_db).unwrap();
        fs::write(
            codeql_db.join("codeql-database.yml"),
            "primaryLanguage: javascript\n",
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
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
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let err = registry
            .execute_tool("systems-hunt:systems-hunt", json!({"maxFindings": 5}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an agent runtime"));

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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        fs::write(
            temp.path().join(".gitignore"),
            ".kuzushi/credentials.json\n",
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let prepared = registry
            .prepare_dispatch_input(
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
                None,
            )
            .unwrap()
            .authorize_explicit_headless_with_delegated_tools(&["patch:finding"]);
        let result = registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
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
        let phase_stages = result
            .pointer("/data/phaseStages")
            .and_then(Value::as_array)
            .expect("actual SAST phase stage receipts");
        assert_eq!(
            phase_stages
                .iter()
                .filter_map(|stage| stage["phase"].as_str())
                .collect::<Vec<_>>(),
            vec!["scan", "review", "prove", "fix"]
        );
        assert!(phase_stages
            .iter()
            .all(|stage| stage["outcome"] == "completed"));

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
        let patch_log = result
            .pointer("/data/artifacts/patchJsonl")
            .and_then(Value::as_str)
            .unwrap();
        let phase_stages_log = result
            .pointer("/data/artifacts/phaseStagesJsonl")
            .and_then(Value::as_str)
            .unwrap();
        assert!(Path::new(summary).exists());
        assert!(summary.ends_with("sast-summary.json"));
        assert!(fs::read_to_string(summary)
            .unwrap()
            .contains("\"verification\""));
        let run_id = result
            .pointer("/data/runId")
            .and_then(Value::as_str)
            .unwrap();
        let run_summary = crate::run_artifacts::load_run_summary(temp.path(), run_id).unwrap();
        assert_eq!(run_summary.status, "completed");
        assert_eq!(run_summary.tool.as_deref(), Some("sast:scan"));
        assert_eq!(run_summary.findings, Some(1));
        assert!(run_summary
            .artifacts
            .iter()
            .any(|artifact| { artifact.label == "sast summary" && artifact.path == summary }));
        let canonical_summary =
            crate::run_artifacts::run_artifact_path(temp.path(), run_id, "run.json");
        assert!(canonical_summary.exists());
        assert!(!fs::read_to_string(canonical_summary)
            .unwrap()
            .contains("\"verification\""));
        assert!(fs::read_to_string(triage_log)
            .unwrap()
            .contains("triage:complete"));
        let verify_log = fs::read_to_string(verify_log).unwrap();
        assert!(verify_log.contains("verification:complete"));
        assert!(!verify_log.contains("patch:complete"));
        assert!(fs::read_to_string(patch_log)
            .unwrap()
            .contains("patch:complete"));
        let phase_stages_log = fs::read_to_string(phase_stages_log).unwrap();
        for phase in ["scan", "review", "prove", "fix"] {
            assert!(
                phase_stages_log.contains(&format!(r#""phase":"{phase}""#)),
                "{phase_stages_log}"
            );
        }

        let finding = store.list_findings(10).unwrap().pop().unwrap();
        assert_eq!(
            result
                .pointer("/data/coreFindings/0/fingerprint")
                .and_then(Value::as_str),
            Some(finding.fingerprint.as_str())
        );
        let patch_results = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(patch_results.len(), 1);
        assert_eq!(patch_results[0].status, PatchStatus::Sound);
        let provenance = patch_results[0]
            .provenance
            .as_ref()
            .expect("new SAST patches must retain detector provenance");
        assert_eq!(provenance.detector_tool.as_deref(), Some("agentic-sast:scan"));
        let detector_run_id = provenance
            .detector_run_id
            .as_deref()
            .expect("detector run reference");
        let detector_summary =
            crate::run_artifacts::load_run_summary(temp.path(), detector_run_id).unwrap();
        assert_eq!(detector_summary.tool.as_deref(), Some("agentic-sast:scan"));
        assert!(crate::run_artifacts::run_artifact_path(
            temp.path(),
            detector_run_id,
            "input.json"
        )
        .is_file());
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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

        let scan_input_path = result
            .pointer("/data/artifacts/input")
            .and_then(Value::as_str)
            .map(Path::new)
            .unwrap();
        assert!(scan_input_path.ends_with(SAST_SCAN_INPUT_FILE));
        let scan_input = fs::read_to_string(scan_input_path).unwrap();
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
        for args in [
            vec!["add", "."],
            vec!["-c", "commit.gpgsign=false", "commit", "-m", "pr"],
        ] {
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("not-seen"));
        let artifact = result
            .pointer("/data/artifacts/whiteboxDiff")
            .and_then(Value::as_str)
            .unwrap();
        let artifact_body = fs::read_to_string(artifact).unwrap();
        assert!(artifact_body.contains("\"changedFiles\""));
        assert!(artifact_body.contains("\"notSeenFindings\""));
        assert!(!artifact_body.contains("\"fixedFindings\""));
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({"binary": binary.display().to_string(), "config": "p/security-audit"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "semgrep:");
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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

    #[cfg(unix)]
    #[test]
    fn semgrep_static_evidence_direct_tool_honors_static_proof_state_option() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("server.js"),
            javascript_fixture_with_line_9_sink(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({
                    "binary": binary.display().to_string(),
                    "mode": "whitebox-static",
                    "staticProofState": "needs_runtime_evidence"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/findings/0/staticProofState")
                .and_then(Value::as_str),
            Some("needs_runtime_evidence")
        );
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        assert_eq!(
            finding.static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
    }

    #[test]
    fn semgrep_missing_binary_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "semgrep:scan",
                json!({"binary": "kuzushi-missing-semgrep"}),
                &ctx,
            )
            .unwrap();
        let err = result["errors"][0].as_str().unwrap();

        assert_eq!(result["ok"], false);
        assert_eq!(result["status"], "failed");
        assert!(err.contains("semgrep: could not find scanner binary"));
        assert!(err.contains("Install Semgrep"));
        assert!(err.contains(r#""binary":"/path/to/semgrep""#));
        assert!(err.contains("kuzushi --target <repo> run semgrep:scan"));
        assert!(err.contains("kuzushi scan <repo> --tasks dep-hygiene,secret-scan"));
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({"binary": binary.display().to_string(), "language": "javascript"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "codeql:");
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
        assert_eq!(
            result
                .pointer("/data/reportSarif/runs/0/results/0/ruleId")
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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

    #[cfg(unix)]
    #[test]
    fn codeql_static_evidence_direct_tool_honors_static_proof_state_option() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("package.json"), "{}\n").unwrap();
        fs::write(
            temp.path().join("server.js"),
            javascript_fixture_with_line_9_sink(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({
                    "binary": binary.display().to_string(),
                    "language": "javascript",
                    "mode": "whitebox-static",
                    "staticProofState": "needs_runtime_evidence"
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/findings/0/staticProofState")
                .and_then(Value::as_str),
            Some("needs_runtime_evidence")
        );
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        assert_eq!(
            finding.static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
    }

    #[test]
    fn codeql_missing_binary_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "codeql:scan",
                json!({
                    "binary": "kuzushi-missing-codeql",
                    "language": "javascript"
                }),
                &ctx,
            )
            .unwrap();
        let err = result["errors"][0].as_str().unwrap();

        assert_eq!(result["ok"], false);
        assert_eq!(result["status"], "failed");
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
            .record_run_started("run-1", workspace.root(), "completed")
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
            .record_auto_triage(
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let result = registry
            .execute_tool(
                "findings:list",
                json!({"severity": ["high"], "verdict": ["tp"], "name": "sql"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "findings:list:");
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
    fn dispatches_report_build_for_run_artifacts() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let source = RunSummary::running(
            "run-report-source",
            "tool",
            Some("secret-scan:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_findings(Some(0));
        write_run_summary(workspace.root(), &source).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let result = registry
            .execute_tool("report:build", json!({"runId": "run-report-source"}), &ctx)
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("Report built for run")));
        assert_eq!(
            result.pointer("/data/sourceRunId").and_then(Value::as_str),
            Some("run-report-source")
        );
        assert!(result
            .get("reportMarkdown")
            .and_then(Value::as_str)
            .is_some_and(|markdown| markdown.contains("# Kuzushi Run Report")));
        let report_path = result
            .pointer("/artifacts/0/path")
            .and_then(Value::as_str)
            .expect("report artifact path");
        let expected_report_path = run_dir(workspace.root(), "run-report-source").join("report.md");
        assert_eq!(Path::new(report_path), expected_report_path.as_path());
        assert!(Path::new(report_path).exists());
        assert!(result.get("warnings").and_then(Value::as_array).is_some());
        assert!(result
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
    }

    #[test]
    fn dispatches_triage_run_with_runtime_and_persists_outcomes() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "triage:run",
                json!({
                    "fingerprint": confirmed.fingerprint.clone(),
                    "model": "openai:gpt-override",
                    "TRIAGE_PROMPT": "Use repository evidence only."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_completed_result_envelope(&result, "[+] Triaged");
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
        assert_eq!(requests[0].model, "openai:gpt-override");
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
            .record_run_started("run-1", workspace.root(), "completed")
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let err = registry
            .execute_tool("triage:run", json!({}), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an agent runtime"));

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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "triage:run",
                json!({"fingerprint": "missing"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("skipped")
        );
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
            .record_run_started("run-1", workspace.root(), "completed")
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
        store.insert_finding("run-1", &finding).unwrap();

        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            result.pointer("/summary").and_then(Value::as_str),
            Some("full-mode:hunt planned 1 chunk over 1 file")
        );
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
    fn full_mode_auto_triage_persists_against_the_inserted_finding_id() {
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
        let runtime = MockRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "full-mode:hunt",
                json!({
                    "autoTriage": true,
                    "autoTriageMaxSteps": 1,
                    "autoTriageDepositUsd": 0.01,
                    "depositUsdPerChunk": 0.01,
                    "maxTokensPerChunk": 4096
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        let stored = store
            .list_findings_filtered(&FindingListFilter::default())
            .unwrap()
            .findings;
        assert_eq!(stored.len(), 1);
        assert!(stored[0].id.is_some());
        assert_eq!(
            stored[0].triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );

        let conn = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
        let evidence_events: i64 = conn
            .query_row(
                "select count(*) from audit_events where subject = 'deep-audit:evidence'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence_events, 1);
    }

    #[test]
    fn full_mode_auto_triage_surfaces_deep_audit_failures() {
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
        let runtime = FailingDeepAuditRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .execute_tool_with_runtime(
                "full-mode:hunt",
                json!({
                    "autoTriage": true,
                    "autoTriageMaxSteps": 1,
                    "autoTriageDepositUsd": 0.01,
                    "depositUsdPerChunk": 0.01,
                    "maxTokensPerChunk": 4096
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("autoTriage deep audit failed"),
            "unexpected error: {error}"
        );
        let stored = store
            .list_findings_filtered(&FindingListFilter::default())
            .unwrap()
            .findings;
        assert_eq!(stored.len(), 1);
        assert!(stored[0].id.is_some());
        assert!(stored[0].triage.is_none());
    }

    #[test]
    fn dispatches_verify_finding_through_runtime() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
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
            .record_auto_triage(
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "verify:finding",
                json!({
                    "fingerprint": finding.fingerprint.clone(),
                    "model": "openai:gpt-verify",
                    "VERIFY_PROMPT": "Prove exploitability with concrete runtime evidence."
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_result_envelope(&result, "verify:finding complete");
        assert_eq!(
            result.pointer("/data/fingerprint").and_then(Value::as_str),
            Some(finding.fingerprint.as_str())
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
        assert_eq!(queries[0].model, "openai:gpt-verify");
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
            .record_run_started("run-1", workspace.root(), "completed")
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            .record_auto_triage(
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
        assert!(err.contains("requires the LangGraph runtime"));

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
        fs::write(
            temp.path().join(".gitignore"),
            ".kuzushi/credentials.json\n",
        )
        .unwrap();
        init_git_repo(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        seed_completed_detector_run(workspace.root(), "run-1", "semgrep:scan");
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
            .record_auto_triage(
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
        let patch_trace = crate::run_artifacts::TraceHandle::jsonl(
            workspace.root(),
            "patch-direct-run",
        );
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&patch_trace),
            cancellation: None,
            authorization: Default::default(),
        };

        let result = execute_authorized_tool_with_runtime(
            &registry,
            "patch:finding",
            json!({
                    "fingerprint": finding.fingerprint.clone(),
                    "model": "openai:gpt-patch",
                    "PATCH_PROMPT": "custom patch system",
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
        assert_completed_result_envelope(&result, "patch:finding ");
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
        assert_eq!(queries[0].model, "openai:gpt-patch");
        assert_eq!(queries[0].system_prompt, "custom patch system");
        let derived = decoded_untrusted_records(
            &queries[0].prompt,
            crate::prompts::boundaries::UNTRUSTED_DERIVED_BEGIN,
            crate::prompts::boundaries::UNTRUSTED_DERIVED_END,
        );
        let finding_record = derived
            .iter()
            .find(|record| record.label == "finding-json")
            .expect("patch prompt must carry the finding as framed derived data");
        let finding_json: Value = serde_json::from_str(&finding_record.content).unwrap();
        assert_eq!(
            finding_json.get("fingerprint").and_then(Value::as_str),
            Some(finding.fingerprint.as_str())
        );
        let repository = decoded_untrusted_records(
            &queries[0].prompt,
            crate::prompts::UNTRUSTED_REPO_BEGIN,
            crate::prompts::UNTRUSTED_REPO_END,
        );
        assert!(repository.iter().any(|record| {
            record.label == "src/db.ts" && record.content.contains("const query = req.query.q")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn patch_synthesis_and_validation_ignore_concurrent_live_tree_edits() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/db.ts"),
            "const query = req.query.q;\n",
        )
        .unwrap();
        fs::write(
            temp.path().join(".gitignore"),
            ".kuzushi/credentials.json\n",
        )
        .unwrap();
        init_git_repo(temp.path());

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        seed_completed_detector_run(workspace.root(), "run-1", "semgrep:scan");
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
            .record_auto_triage(
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
        let runtime = MutatingPatchRuntime::new(temp.path().to_path_buf());
        let patch_trace = crate::run_artifacts::TraceHandle::jsonl(
            workspace.root(),
            "patch-mutation-run",
        );
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&patch_trace),
            cancellation: None,
            authorization: Default::default(),
        };

        let result = execute_authorized_tool_with_runtime(
            &registry,
            "patch:finding",
            json!({
                "fingerprint": finding.fingerprint,
                "model": "openai:gpt-patch",
                "maxIterations": 1
            }),
            &ctx,
            Some(&runtime),
        )
        .unwrap();

        assert_eq!(result.pointer("/data/status"), Some(&json!("SOUND")));
        let observations = runtime.observations();
        assert_eq!(observations.len(), 1);
        let (request, source) = &observations[0];
        assert_ne!(request.cwd, workspace.root());
        assert!(request
            .cwd
            .starts_with(workspace.root().join(".kuzushi/worktrees")));
        assert_eq!(source, "const query = req.query.q;\n");
        assert!(request.prompt.contains("const query = req.query.q"));
        assert!(!request.prompt.contains("concurrent_uncommitted_change"));
        assert_eq!(
            fs::read_to_string(temp.path().join("src/db.ts")).unwrap(),
            "const query = concurrent_uncommitted_change;\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn patch_finding_requires_triage_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join(".gitignore"),
            ".kuzushi/credentials.json\n",
        )
        .unwrap();
        init_git_repo(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        seed_completed_detector_run(workspace.root(), "run-1", "semgrep:scan");
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
        let patch_trace = crate::run_artifacts::TraceHandle::jsonl(
            workspace.root(),
            "patch-policy-run",
        );
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&patch_trace),
            cancellation: None,
            authorization: Default::default(),
        };

        let result = execute_authorized_tool(
            &registry,
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
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let err = execute_authorized_tool(
            &registry,
            "patch:finding",
            json!({"fingerprint": finding.fingerprint.clone()}),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires the LangGraph runtime"));

        let runtime = MockRuntime::new();
        let err = execute_authorized_tool_with_runtime(
            &registry,
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
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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

    fn assert_completed_result_envelope(result: &Value, summary_prefix: &str) {
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with(summary_prefix)));
        assert!(result
            .get("artifacts")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
        assert!(result
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
        assert!(result
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
    }

    #[test]
    fn every_model_backed_planning_tool_declares_editable_prompts() {
        let registry = ModuleRegistry::with_v2_builtins();
        let tools = [
            "x-ray:run",
            "threat-model:build",
            "agentic-sast:scan",
            "taint-iris-next:hunt",
            "offense-review:threat-hunt",
            "systems-hunt:systems-hunt",
            "triage:run",
            "verify:finding",
            "patch:finding",
        ];

        for name in tools {
            let descriptor = registry
                .resolve_tool(name)
                .expect("planning tool descriptor");
            assert!(
                !descriptor.prompts.is_empty(),
                "{name} has no editable prompt"
            );
        }
        assert_eq!(
            registry
                .resolve_tool("systems-hunt:systems-hunt")
                .unwrap()
                .prompts
                .len(),
            3
        );
    }

    #[test]
    fn model_backed_prompt_subtools_declare_their_runtime_roles() {
        let registry = ModuleRegistry::with_v2_builtins();
        let expected = [
            ("taint-iris-next:finding-review", 1),
            ("taint-iris-next:catalog", 1),
            ("taint-iris-next:codeql-db", 1),
            ("systems-hunt:systems-invariant-extract", 1),
            ("systems-hunt:systems-trigger-synth", 1),
            ("systems-hunt:deep-semantic-cwe-select", 1),
            ("systems-hunt:deep-semantic-hunt", 1),
            ("sast:scan", 2),
        ];

        for (name, prompt_count) in expected {
            assert_eq!(
                registry.resolve_tool(name).unwrap().prompts.len(),
                prompt_count,
                "{name} prompt role count"
            );
        }
    }

    fn assert_route_path(routes: &[Value], expected: &str) {
        assert!(
            routes
                .iter()
                .any(|route| route_path(route) == Some(expected)),
            "missing route {expected}: {routes:#?}"
        );
    }

    fn assert_no_route_path(routes: &[Value], unexpected: &str) {
        assert!(
            routes
                .iter()
                .all(|route| route_path(route) != Some(unexpected)),
            "unexpected route {unexpected}: {routes:#?}"
        );
    }

    fn assert_route(routes: &[Value], method: &str, path: &str, framework: &str) {
        assert!(
            routes.iter().any(|route| {
                route.get("method").and_then(Value::as_str) == Some(method)
                    && route_endpoint(route) == Some(path)
                    && route.get("framework").and_then(Value::as_str) == Some(framework)
            }),
            "missing route {method} {path} {framework}: {routes:#?}"
        );
    }

    fn route_endpoint(route: &Value) -> Option<&str> {
        route
            .get("route")
            .or_else(|| route.get("path"))
            .and_then(Value::as_str)
    }

    fn route_path(route: &Value) -> Option<&str> {
        route
            .get("path")
            .or_else(|| route.get("route"))
            .and_then(Value::as_str)
    }
}
