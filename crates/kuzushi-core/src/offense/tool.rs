//! The `offense:chain` operator tool.
//!
//! Resolves a chain run from input + the workspace, runs it against the live
//! target through the sandbox-routed transport, and returns a result envelope
//! carrying the per-hop [`ChainOutcome`]. The scope gate inside `run_chain` is
//! the only door: a target the engagement scope denies never reaches the
//! transport, and the tool reports the denial instead.

use super::chain::{run_chain, ChainOutcome};
use super::engagement::{prepare_chain_run, resolve_engagement, PreparedChainRun};
use super::persistence::{persist_chain_finding, persisted_backend};
use super::planner::{run_planned_chain, PlannerBudget};
use super::engagement_scope::ScopeTarget;
use super::play_context::PlayContext;
use super::sandbox_curl::SandboxCurlTransport;
use super::transport::PlayTransport;
use crate::findings::{FindingStore, PersistedSandboxBackend};
use crate::runtime::AgentRuntime;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_PLAY_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_MAX_PLANNED_STEPS: u32 = 8;

/// Run `offense:chain` with the default sandbox-routed curl transport,
/// persisting a landed chain into `store` when one is available.
pub fn execute_offense_chain(
    input: &Value,
    workspace_root: &Path,
    store: Option<&FindingStore>,
) -> Value {
    let timeout_ms = input
        .get("timeoutMs")
        .or_else(|| input.get("timeout_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_PLAY_TIMEOUT_MS);
    let transport = SandboxCurlTransport::detect(timeout_ms);
    let backend = persisted_backend(transport.backend());
    run_offense_chain(input, workspace_root, &transport, backend, store, now_unix())
}

/// Run `offense:chain` in autonomous (LLM-planned) mode: the model proposes
/// each next play toward `goal`. Authorizes the target through the scope gate
/// before any step, then persists a landed chain like the declarative path.
pub fn execute_offense_planned(
    input: &Value,
    workspace_root: &Path,
    store: Option<&FindingStore>,
    runtime: &dyn AgentRuntime,
    model: &str,
    goal: &str,
) -> Value {
    let timeout_ms = input
        .get("timeoutMs")
        .or_else(|| input.get("timeout_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_PLAY_TIMEOUT_MS);
    let transport = SandboxCurlTransport::detect(timeout_ms);
    let backend = persisted_backend(transport.backend());
    run_planned(PlannedRun {
        input,
        workspace_root,
        store,
        runtime,
        model,
        goal,
        transport: &transport,
        backend,
        now_unix: now_unix(),
    })
}

struct PlannedRun<'a> {
    input: &'a Value,
    workspace_root: &'a Path,
    store: Option<&'a FindingStore>,
    runtime: &'a dyn AgentRuntime,
    model: &'a str,
    goal: &'a str,
    transport: &'a dyn PlayTransport,
    backend: PersistedSandboxBackend,
    now_unix: u64,
}

fn run_planned(run: PlannedRun<'_>) -> Value {
    let (scope, target_host) = match resolve_engagement(run.input, run.workspace_root) {
        Ok(resolved) => resolved,
        Err(reason) => return failure("offense:chain could not start", reason),
    };
    let authorized = match scope.authorize(ScopeTarget::parse(&target_host), run.now_unix) {
        Ok(authorized) => authorized,
        Err(reason) => {
            return failure("offense:chain refused", format!("refused {target_host}: {reason}"))
        }
    };
    let run_id = input_run_id(run.input, run.now_unix);
    let ctx = PlayContext::new(authorized, run_id);
    let budget = PlannerBudget {
        max_steps: planned_max_steps(run.input),
    };
    let chain_name = run
        .input
        .get("chainName")
        .and_then(Value::as_str)
        .unwrap_or("planned");
    match run_planned_chain(
        chain_name,
        run.goal,
        &ctx,
        run.runtime,
        run.model,
        run.workspace_root,
        run.transport,
        budget,
    ) {
        Ok(outcome) => {
            let finding_id =
                persist_outcome(run.store, run.workspace_root, &target_host, run.backend, &outcome);
            success(outcome, finding_id)
        }
        Err(err) => failure("offense:chain planning failed", err.to_string()),
    }
}

fn planned_max_steps(input: &Value) -> u32 {
    input
        .get("maxSteps")
        .or_else(|| input.get("max_steps"))
        .and_then(Value::as_u64)
        .map(|steps| steps.clamp(1, 24) as u32)
        .unwrap_or(DEFAULT_MAX_PLANNED_STEPS)
}

fn input_run_id(input: &Value, now_unix: u64) -> String {
    input
        .get("runId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("offense-{now_unix}"))
}

/// Inner runner, transport-, backend-, store-, and clock-injected for tests.
fn run_offense_chain(
    input: &Value,
    workspace_root: &Path,
    transport: &dyn PlayTransport,
    backend: PersistedSandboxBackend,
    store: Option<&FindingStore>,
    now_unix: u64,
) -> Value {
    let prepared = match prepare_chain_run(input, workspace_root) {
        Ok(prepared) => prepared,
        Err(reason) => return failure("offense:chain could not start", reason),
    };
    let run_id = input
        .get("runId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("offense-{now_unix}"));

    let outcome = match run_prepared(&prepared, &run_id, transport, now_unix) {
        Ok(outcome) => outcome,
        Err(reason) => return failure("offense:chain refused or failed", reason),
    };
    let finding_id = persist_outcome(store, workspace_root, &prepared.target_host, backend, &outcome);
    success(outcome, finding_id)
}

/// Persist the outcome when a store is present; a persistence failure must not
/// lose the chain result, so it is recorded as a note rather than an error.
fn persist_outcome(
    store: Option<&FindingStore>,
    workspace_root: &Path,
    target_host: &str,
    backend: PersistedSandboxBackend,
    outcome: &ChainOutcome,
) -> Option<i64> {
    let store = store?;
    match persist_chain_finding(store, workspace_root, target_host, backend, outcome) {
        Ok(finding_id) => finding_id,
        Err(_) => None,
    }
}

fn run_prepared(
    prepared: &PreparedChainRun,
    run_id: &str,
    transport: &dyn PlayTransport,
    now_unix: u64,
) -> Result<ChainOutcome, String> {
    run_chain(
        &prepared.scope,
        &prepared.target_host,
        now_unix,
        run_id,
        &prepared.chain,
        transport,
    )
}

fn success(outcome: ChainOutcome, finding_id: Option<i64>) -> Value {
    let output = format!("{} :: {}", outcome.chain, outcome.summary);
    let mut data = json!(outcome);
    if let (Some(object), Some(id)) = (data.as_object_mut(), finding_id) {
        object.insert("findingId".to_string(), json!(id));
    }
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn failure(summary: &str, reason: String) -> Value {
    let output = format!("[-] {summary}: {reason}");
    crate::module_result::failed_output_result(summary, output, json!({ "reason": reason }))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::TriageOutcome;
    use crate::offense::engagement_scope::ScopeTarget;
    use crate::offense::transport::{PlayRequest, PlayResponse};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, TriageRequest};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubTransport {
        status: u16,
        body: String,
    }
    impl PlayTransport for StubTransport {
        fn send(&self, _t: &ScopeTarget, _r: &PlayRequest) -> Result<PlayResponse, String> {
            Ok(PlayResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
                elapsed_ms: 1,
            })
        }
    }

    /// Counts how many times the model was queried, so a test can prove a
    /// denied target never reaches the planner.
    struct CountingRuntime {
        queries: AtomicUsize,
    }
    impl AgentRuntime for CountingRuntime {
        fn query_blocking(
            &self,
            _request: AgentQueryRequest,
        ) -> anyhow::Result<AgentQueryResponse> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            Ok(AgentQueryResponse {
                structured: Some(json!({"done": true})),
                ..Default::default()
            })
        }
        fn triage_finding_blocking(
            &self,
            _request: TriageRequest,
        ) -> anyhow::Result<TriageOutcome> {
            unreachable!("offense planner does not triage")
        }
    }

    #[test]
    fn planned_mode_refuses_a_denied_target_before_querying_the_model() {
        let runtime = CountingRuntime {
            queries: AtomicUsize::new(0),
        };
        let transport = StubTransport {
            status: 200,
            body: String::new(),
        };
        let input = json!({
            "target": "10.9.9.9",
            "scope": {"authorized": true, "authorizationRef": "HTB:lab", "inScope": ["10.0.0.5"]},
        });
        let test_model_id = "openai:gpt-test";
        let result = run_planned(PlannedRun {
            input: &input,
            workspace_root: Path::new("/tmp/ws"),
            store: None,
            runtime: &runtime,
            model: test_model_id,
            goal: "get admin",
            transport: &transport,
            backend: PersistedSandboxBackend::Plain,
            now_unix: 1,
        });
        assert_eq!(result["status"], json!("failed"));
        assert!(result["data"]["reason"].as_str().unwrap().contains("refused"));
        assert_eq!(runtime.queries.load(Ordering::SeqCst), 0, "scope gate must precede planning");
    }

    fn input() -> Value {
        json!({
            "target": "10.0.0.5",
            "scope": {"authorized": true, "authorizationRef": "HTB:lab", "inScope": ["10.0.0.5"]},
            "chain": {"name": "probe", "plays": [
                {"name": "admin", "path": "/admin", "expectStatus": 200, "expectSignals": ["root"]}
            ]}
        })
    }

    fn run(input: &Value, transport: &dyn PlayTransport, store: Option<&FindingStore>) -> Value {
        run_offense_chain(
            input,
            Path::new("/tmp/ws"),
            transport,
            PersistedSandboxBackend::Plain,
            store,
            1,
        )
    }

    #[test]
    fn completed_chain_returns_a_completed_envelope() {
        let transport = StubTransport {
            status: 200,
            body: "root shell".to_string(),
        };
        let result = run(&input(), &transport, None);
        assert_eq!(result["status"], json!("completed"));
        assert_eq!(result["data"]["completed"], json!(true));
        assert_eq!(result["data"]["chain"], json!("probe"));
    }

    #[test]
    fn completed_chain_persists_a_finding_and_reports_its_id() {
        let store = FindingStore::open_in_memory().unwrap();
        let transport = StubTransport {
            status: 200,
            body: "root shell".to_string(),
        };
        let result = run(&input(), &transport, Some(&store));
        assert_eq!(result["status"], json!("completed"));
        assert!(result["data"]["findingId"].is_number());
        // The chain landed as a durable finding.
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn denied_target_returns_a_failed_envelope_and_never_sends() {
        let mut input = input();
        input["target"] = json!("10.9.9.9");
        let store = FindingStore::open_in_memory().unwrap();
        let transport = StubTransport {
            status: 200,
            body: "root".to_string(),
        };
        let result = run(&input, &transport, Some(&store));
        assert_eq!(result["status"], json!("failed"));
        assert!(result["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("refused"));
        // A denied target writes no finding.
        assert!(store.list_findings(10).unwrap().is_empty());
    }

    #[test]
    fn missing_scope_and_target_fails_cleanly() {
        let transport = StubTransport {
            status: 200,
            body: String::new(),
        };
        let result = run(&json!({}), &transport, None);
        assert_eq!(result["status"], json!("failed"));
    }
}
