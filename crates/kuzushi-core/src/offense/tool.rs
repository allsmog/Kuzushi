//! The `offense:chain` operator tool.
//!
//! Resolves a chain run from input + the workspace, runs it against the live
//! target through the sandbox-routed transport, and returns a result envelope
//! carrying the per-hop [`ChainOutcome`]. The scope gate inside `run_chain` is
//! the only door: a target the engagement scope denies never reaches the
//! transport, and the tool reports the denial instead.

use super::chain::{run_chain, ChainOutcome};
use super::engagement::{prepare_chain_run, resolve_engagement, PreparedChainRun};
use super::engagement_scope::ScopeTarget;
use super::observer::HopObserver;
use super::persistence::{persist_chain_finding_for_run, persisted_backend};
use super::planner::{run_planned_chain, PlannerBudget};
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
const PERSISTENCE_WARNING: &str = "live chain persistence did not complete cleanly; this result is partial and durable finding/proof state is unconfirmed";

/// Run `offense:chain` with the default sandbox-routed curl transport,
/// persisting a landed chain into `store` when one is available.
pub fn execute_offense_chain(
    input: &Value,
    workspace_root: &Path,
    store: Option<&FindingStore>,
    observer: &dyn HopObserver,
) -> Value {
    execute_offense_chain_for_run(input, workspace_root, store, observer, None)
}

pub fn execute_offense_chain_for_run(
    input: &Value,
    workspace_root: &Path,
    store: Option<&FindingStore>,
    observer: &dyn HopObserver,
    verification_run_id: Option<String>,
) -> Value {
    let timeout_ms = input
        .get("timeoutMs")
        .or_else(|| input.get("timeout_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_PLAY_TIMEOUT_MS);
    let transport = SandboxCurlTransport::detect(timeout_ms);
    let backend = persisted_backend(transport.backend());
    run_offense_chain(
        input,
        workspace_root,
        &transport,
        backend,
        store,
        now_unix(),
        observer,
        verification_run_id.as_deref(),
    )
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
    observer: &dyn HopObserver,
) -> Value {
    execute_offense_planned_for_run(
        input,
        workspace_root,
        store,
        runtime,
        model,
        goal,
        observer,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_offense_planned_for_run(
    input: &Value,
    workspace_root: &Path,
    store: Option<&FindingStore>,
    runtime: &dyn AgentRuntime,
    model: &str,
    goal: &str,
    observer: &dyn HopObserver,
    verification_run_id: Option<String>,
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
        observer,
        verification_run_id,
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
    observer: &'a dyn HopObserver,
    verification_run_id: Option<String>,
}

fn run_planned(run: PlannedRun<'_>) -> Value {
    let (target_host, ctx) = match prepare_planned_context(&run) {
        Ok(prepared) => prepared,
        Err(error) => return error,
    };
    let result = execute_planned_run(&run, &ctx);
    finish_planned_run(&run, &target_host, result)
}

fn prepare_planned_context(run: &PlannedRun<'_>) -> Result<(String, PlayContext), Value> {
    let (scope, target_host) = resolve_engagement(run.input, run.workspace_root)
        .map_err(|reason| failure("offense:chain could not start", reason))?;
    let authorized = scope
        .authorize(ScopeTarget::parse(&target_host), run.now_unix)
        .map_err(|reason| {
            failure(
                "offense:chain refused",
                format!("refused {target_host}: {reason}"),
            )
        })?;
    let ctx = PlayContext::new(authorized, input_run_id(run.input, run.now_unix));
    Ok((target_host, ctx))
}

fn execute_planned_run(run: &PlannedRun<'_>, ctx: &PlayContext) -> anyhow::Result<ChainOutcome> {
    run_planned_chain(
        chain_name(run.input),
        run.goal,
        ctx,
        run.runtime,
        run.model,
        run.workspace_root,
        run.transport,
        PlannerBudget {
            max_steps: planned_max_steps(run.input),
        },
        run.observer,
    )
}

fn finish_planned_run(
    run: &PlannedRun<'_>,
    target_host: &str,
    result: anyhow::Result<ChainOutcome>,
) -> Value {
    match result {
        Ok(outcome) => {
            let persistence = persist_outcome(
                run.store,
                run.workspace_root,
                target_host,
                run.backend,
                &outcome,
                run.verification_run_id.as_deref(),
            );
            let warnings = isolation_warnings(run.backend, target_host);
            finish_outcome(outcome, persistence, warnings)
        }
        Err(err) => failure("offense:chain planning failed", err.to_string()),
    }
}

fn chain_name(input: &Value) -> &str {
    input
        .get("chainName")
        .and_then(Value::as_str)
        .unwrap_or("planned")
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
    observer: &dyn HopObserver,
    verification_run_id: Option<&str>,
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

    let outcome = match run_prepared(&prepared, &run_id, transport, now_unix, observer) {
        Ok(outcome) => outcome,
        Err(reason) => return failure("offense:chain refused or failed", reason),
    };
    let persistence = persist_outcome(
        store,
        workspace_root,
        &prepared.target_host,
        backend,
        &outcome,
        verification_run_id,
    );
    let warnings = isolation_warnings(backend, &prepared.target_host);
    finish_outcome(outcome, persistence, warnings)
}

/// Persist the outcome when a store is present. A persistence failure is part
/// of the operator-visible terminal state: live evidence whose durable
/// finding/proof closure could not be confirmed must never be reported as a
/// complete result.
fn persist_outcome(
    store: Option<&FindingStore>,
    workspace_root: &Path,
    target_host: &str,
    backend: PersistedSandboxBackend,
    outcome: &ChainOutcome,
    verification_run_id: Option<&str>,
) -> anyhow::Result<Option<i64>> {
    let Some(store) = store else {
        return Ok(None);
    };
    persist_chain_finding_for_run(
        store,
        workspace_root,
        target_host,
        backend,
        outcome,
        verification_run_id,
    )
}

fn run_prepared(
    prepared: &PreparedChainRun,
    run_id: &str,
    transport: &dyn PlayTransport,
    now_unix: u64,
    observer: &dyn HopObserver,
) -> Result<ChainOutcome, String> {
    run_chain(
        &prepared.scope,
        &prepared.target_host,
        now_unix,
        run_id,
        &prepared.chain,
        transport,
        observer,
    )
}

fn finish_outcome(
    outcome: ChainOutcome,
    persistence: anyhow::Result<Option<i64>>,
    mut warnings: Vec<String>,
) -> Value {
    match persistence {
        Ok(finding_id) => success(outcome, finding_id, warnings),
        Err(_) => {
            warnings.push(PERSISTENCE_WARNING.to_string());
            outcome_result(outcome, None, warnings, true)
        }
    }
}

fn success(outcome: ChainOutcome, finding_id: Option<i64>, warnings: Vec<String>) -> Value {
    outcome_result(outcome, finding_id, warnings, false)
}

fn outcome_result(
    outcome: ChainOutcome,
    finding_id: Option<i64>,
    warnings: Vec<String>,
    partial: bool,
) -> Value {
    let observed = crate::runtime::RuntimeCost::from_usd(
        outcome.cost_usd,
        "offense chain outcome cost",
    )
    .expect("offense planner validates cost before constructing the outcome");
    let cost = if outcome.cost_usd_exact {
        crate::runtime::RuntimeCostReport::known(observed)
    } else {
        crate::runtime::RuntimeCostReport::incomplete(observed)
    };
    let mut output = format!("{} :: {}", outcome.chain, outcome.summary);
    for warning in &warnings {
        output.push_str(&format!("\n[!] {warning}"));
    }
    let data = success_data(outcome, finding_id, &warnings);
    let mut result = if partial {
        crate::module_result::partial_output_result(
            output.clone(),
            output,
            warnings.iter().map(|warning| json!(warning)).collect(),
            data,
        )
    } else {
        crate::module_result::completed_output_result(output.clone(), output, data)
    };
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
}

fn success_data(outcome: ChainOutcome, finding_id: Option<i64>, warnings: &[String]) -> Value {
    let mut data = json!(outcome);
    let Some(object) = data.as_object_mut() else {
        return data;
    };
    if let Some(id) = finding_id {
        object.insert("findingId".to_string(), json!(id));
    }
    if !warnings.is_empty() {
        object.insert("warnings".to_string(), json!(warnings));
    }
    data
}

/// Warn when live traffic goes through the unsandboxed `Plain` backend at a
/// target that is not loopback — the operator's host is not isolated from a
/// host they don't control. Loopback (a local lab) is fine; anything else
/// should run under bwrap/podman.
fn isolation_warnings(backend: PersistedSandboxBackend, target_host: &str) -> Vec<String> {
    if backend == PersistedSandboxBackend::Plain && !is_loopback_target(target_host) {
        return vec![format!(
            "live traffic to {target_host} ran through the unsandboxed Plain backend (no bwrap/podman on PATH); install one to isolate offensive traffic from your host"
        )];
    }
    Vec::new()
}

fn is_loopback_target(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost")
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
    use crate::offense::observer::NoopObserver;
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
            observer: &NoopObserver,
            verification_run_id: None,
        });
        assert_eq!(result["status"], json!("failed"));
        assert!(result["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("refused"));
        assert_eq!(
            runtime.queries.load(Ordering::SeqCst),
            0,
            "scope gate must precede planning"
        );
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
            &NoopObserver,
            None,
        )
    }

    fn landed_outcome() -> ChainOutcome {
        ChainOutcome {
            chain: "probe".to_string(),
            target: "10.0.0.5".to_string(),
            steps: vec![crate::offense::PlayOutcome::new("admin", "10.0.0.5").exploited(
                "root shell".to_string(),
                vec!["root".to_string()],
            )],
            completed: true,
            summary: "chain complete".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: true,
        }
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
    fn persistence_failure_marks_landed_chain_partial_and_visible() {
        let result = finish_outcome(
            landed_outcome(),
            Err(anyhow::anyhow!("sqlite failure at /secret/operator/path")),
            Vec::new(),
        );

        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["status"], json!("partial"));
        assert_eq!(result["data"]["completed"], json!(true));
        assert!(result["data"]["findingId"].is_null());
        assert_eq!(result["warnings"], json!([PERSISTENCE_WARNING]));
        assert_eq!(result["data"]["warnings"], json!([PERSISTENCE_WARNING]));
        assert!(result["output"].as_str().unwrap().contains(PERSISTENCE_WARNING));
    }

    #[test]
    fn persistence_failure_does_not_echo_backend_error_details() {
        let secret_marker = "do-not-leak-this-path-or-token";
        let result = finish_outcome(
            landed_outcome(),
            Err(anyhow::anyhow!(secret_marker)),
            Vec::new(),
        );
        let encoded = serde_json::to_string(&result).unwrap();

        assert!(!encoded.contains(secret_marker), "{encoded}");
        assert!(encoded.contains(PERSISTENCE_WARNING));
    }

    #[test]
    fn completed_chain_persists_a_finding_and_reports_its_id() {
        let temp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(temp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
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
    fn completed_chain_threads_outer_run_into_verification_provenance() {
        let store = FindingStore::open_in_memory().unwrap();
        let transport = StubTransport {
            status: 200,
            body: "root shell".to_string(),
        };
        let result = run_offense_chain(
            &input(),
            Path::new("/tmp/ws"),
            &transport,
            PersistedSandboxBackend::Plain,
            Some(&store),
            1,
            &NoopObserver,
            Some("tool-outer"),
        );

        let finding_id = result["data"]["findingId"].as_i64().unwrap();
        let finding = store
            .list_findings(10)
            .unwrap()
            .into_iter()
            .find(|finding| finding.id == Some(finding_id))
            .unwrap();
        let proof = store.get_latest_verification(finding_id).unwrap().unwrap();
        assert_eq!(proof.verification_run_id.as_deref(), Some("tool-outer"));
        assert_eq!(proof.verified_scan_id, finding.scan_id);
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

    #[test]
    fn loopback_target_under_plain_backend_warns_nothing() {
        assert!(isolation_warnings(PersistedSandboxBackend::Plain, "127.0.0.1").is_empty());
        assert!(isolation_warnings(PersistedSandboxBackend::Plain, "localhost").is_empty());
        assert!(isolation_warnings(PersistedSandboxBackend::Plain, "::1").is_empty());
    }

    #[test]
    fn non_loopback_under_plain_backend_warns() {
        let warnings = isolation_warnings(PersistedSandboxBackend::Plain, "10.0.0.5");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("unsandboxed Plain backend"));
    }

    #[test]
    fn isolating_backend_never_warns() {
        assert!(isolation_warnings(PersistedSandboxBackend::Bwrap, "10.0.0.5").is_empty());
        assert!(isolation_warnings(PersistedSandboxBackend::Podman, "box.htb").is_empty());
    }

    #[test]
    fn non_loopback_plain_chain_surfaces_the_warning_in_the_envelope() {
        let transport = StubTransport {
            status: 200,
            body: "root shell".to_string(),
        };
        // The `run` helper uses the Plain backend; input() targets 10.0.0.5.
        let result = run(&input(), &transport, None);
        assert_eq!(result["status"], json!("completed"));
        let warnings = result["data"]["warnings"].as_array().expect("warnings");
        assert!(warnings[0].as_str().unwrap().contains("Plain backend"));
    }
}
