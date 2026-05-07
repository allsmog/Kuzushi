//! Per-model gating wrapper around an [`AgentRuntime`].
//!
//! Multi-step tool loops (e.g. `triage:deep`) issue back-to-back HTTP
//! calls inside a single tool dispatch. Without coordination, N
//! concurrent deep audits all hammer the same per-account rate limiter
//! and burn through quota or hit 429s. [`GatedRuntime`] threads each
//! `next_step_blocking` invocation through a [`ModelGate`] permit so
//! the per-model concurrency cap from `models.toml [concurrency]` (or
//! [`default_concurrency_for`]) bounds in-flight tool-loop steps the
//! same way it already bounds Stage-2 triage dispatch in `run_triage`.
//!
//! All other [`AgentRuntime`] methods delegate straight to the inner
//! runtime — only the tool-loop step is gated, because that is the
//! only path that today fires uncoordinated calls inside a single tool.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::runtime::Handle;

use crate::concurrency::{ModelGate, Priority};
use crate::findings::TriageOutcome;
use crate::runtime::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    LoopHistoryEntry, ModelTier, SubagentRole, TriageRequest,
};

/// Wraps an [`AgentRuntime`] and acquires a [`ModelGate`] permit before
/// each `next_step_blocking` call. The permit drops when the inner call
/// returns, so a saturated gate naturally serialises further steps onto
/// the same model.
pub struct GatedRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    gate: Arc<ModelGate>,
    handle: Option<Handle>,
    priority: Priority,
    model_hint: String,
}

impl<'a> GatedRuntime<'a> {
    pub fn new(
        inner: &'a dyn AgentRuntime,
        gate: Arc<ModelGate>,
        handle: Option<Handle>,
        priority: Priority,
        model_hint: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            gate,
            handle,
            priority,
            model_hint: model_hint.into(),
        }
    }

    /// Resolve a tokio handle for blocking permit acquisition. Reuse the
    /// caller's handle when one was supplied (the common case — the
    /// outer `#[tokio::main]` runtime). Otherwise reuse whatever is
    /// `Handle::try_current` returns. Building a fresh runtime *inside*
    /// an outer runtime panics on drop, so the `try_current` check is
    /// load-bearing — falling through to a fresh `current_thread`
    /// runtime only when there is genuinely no enclosing runtime.
    fn block_on_acquire(&self) -> crate::concurrency::PriorityPermit {
        let fut = self.gate.acquire(&self.model_hint, self.priority);
        // Calling `Handle::block_on` from inside a tokio worker
        // thread panics with "Cannot start a runtime from within a
        // runtime". `block_in_place` is the supported escape hatch:
        // it temporarily marks the current task as blocking so the
        // scheduler can drive other work while we wait for the
        // permit. Required for any path that runs under
        // `#[tokio::main]` (every CLI / shell flow).
        if let Some(h) = &self.handle {
            return tokio::task::block_in_place(|| h.block_on(fut));
        }
        if let Ok(h) = Handle::try_current() {
            return tokio::task::block_in_place(|| h.block_on(fut));
        }
        // No tokio context at all — synchronous test path. A fresh
        // single-thread runtime is the only way to drive the future.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current_thread runtime for GatedRuntime acquire");
        rt.block_on(fut)
    }
}

#[async_trait]
impl AgentRuntime for GatedRuntime<'_> {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.inner.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.inner.triage_finding_blocking(request)
    }

    fn model_for_tier(&self, tier: ModelTier, configured: &str) -> String {
        self.inner.model_for_tier(tier, configured)
    }

    fn model_for_role(&self, role_key: &str, configured: &str) -> String {
        self.inner.model_for_role(role_key, configured)
    }

    fn spawn_subagent_blocking(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        self.inner.spawn_subagent_blocking(role, request)
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let _permit = self.block_on_acquire();
        self.inner.next_step_blocking(request, history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity, TriageVerdict};
    use crate::runtime::{AgentTool, ToolCall};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Recording mock that counts invocations of every trait method we
    /// expect [`GatedRuntime`] to delegate.
    #[derive(Default)]
    struct RecordingRuntime {
        query_calls: Mutex<u32>,
        triage_calls: Mutex<u32>,
        next_step_calls: Mutex<u32>,
        spawn_calls: Mutex<u32>,
        tier_calls: Mutex<u32>,
        role_calls: Mutex<u32>,
        supports_tools_value: bool,
    }

    impl AgentRuntime for RecordingRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            *self.query_calls.lock().unwrap() += 1;
            Ok(AgentQueryResponse {
                text: "ok".to_string(),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            *self.triage_calls.lock().unwrap() += 1;
            Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.5,
                rationale: "delegated".to_string(),
                cost_usd: 0.0,
            })
        }

        fn model_for_tier(&self, _tier: ModelTier, configured: &str) -> String {
            *self.tier_calls.lock().unwrap() += 1;
            format!("tier:{configured}")
        }

        fn model_for_role(&self, role_key: &str, configured: &str) -> String {
            *self.role_calls.lock().unwrap() += 1;
            format!("role:{role_key}:{configured}")
        }

        fn spawn_subagent_blocking(
            &self,
            _role: SubagentRole,
            _request: AgentQueryRequest,
        ) -> Result<AgentQueryResponse> {
            *self.spawn_calls.lock().unwrap() += 1;
            Ok(AgentQueryResponse::default())
        }

        fn supports_tools(&self) -> bool {
            self.supports_tools_value
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            *self.next_step_calls.lock().unwrap() += 1;
            Ok(AgentLoopStep::Final {
                text: "done".to_string(),
                structured: None,
                cost_usd: Some(0.001),
            })
        }
    }

    fn sample_query() -> AgentQueryRequest {
        AgentQueryRequest::new(
            "anthropic:claude-haiku-4-5",
            PathBuf::from("."),
            "system",
            "prompt",
        )
    }

    fn sample_triage_request() -> TriageRequest {
        let finding = Finding::new_semgrep("rule.x", "src/x.rs", 1, Some(1), Severity::High, "x");
        TriageRequest {
            model: "anthropic:claude-haiku-4-5".to_string(),
            cwd: PathBuf::from("."),
            finding,
            prompt_template: None,
        }
    }

    fn sample_loop_request() -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "anthropic:claude-haiku-4-5".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: String::new(),
            prompt: String::new(),
            tools: Vec::<AgentTool>::new(),
            max_steps: 1,
        }
    }

    #[test]
    fn delegates_every_passthrough_method_to_inner_runtime() {
        let inner = RecordingRuntime {
            supports_tools_value: true,
            ..Default::default()
        };
        let gate = Arc::new(ModelGate::new());
        gate.set_cap("anthropic:claude-haiku-4-5", 4);
        let gated = GatedRuntime::new(
            &inner,
            gate,
            None,
            Priority::Normal,
            "anthropic:claude-haiku-4-5",
        );

        gated.query_blocking(sample_query()).unwrap();
        gated
            .triage_finding_blocking(sample_triage_request())
            .unwrap();
        let tier = gated.model_for_tier(ModelTier::Cheap, "configured-model");
        let role = gated.model_for_role("deep_auditor", "configured-model");
        gated
            .spawn_subagent_blocking(SubagentRole::Generic, sample_query())
            .unwrap();
        let supports = gated.supports_tools();
        let req = sample_loop_request();
        gated.next_step_blocking(&req, &[]).unwrap();

        assert_eq!(*inner.query_calls.lock().unwrap(), 1);
        assert_eq!(*inner.triage_calls.lock().unwrap(), 1);
        assert_eq!(*inner.spawn_calls.lock().unwrap(), 1);
        assert_eq!(*inner.tier_calls.lock().unwrap(), 1);
        assert_eq!(*inner.role_calls.lock().unwrap(), 1);
        assert_eq!(*inner.next_step_calls.lock().unwrap(), 1);
        assert_eq!(tier, "tier:configured-model");
        assert_eq!(role, "role:deep_auditor:configured-model");
        assert!(supports);
    }

    /// Scripted runtime that records the wall-clock start of each
    /// `next_step_blocking` and sleeps `latency` to simulate an HTTP
    /// round-trip. Used to assert the gate serialises calls.
    struct LatencyRuntime {
        latency: Duration,
        starts: Mutex<Vec<Instant>>,
    }

    impl AgentRuntime for LatencyRuntime {
        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not exercised in cap-enforcement test")
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.starts.lock().unwrap().push(Instant::now());
            std::thread::sleep(self.latency);
            Ok(AgentLoopStep::Final {
                text: "done".to_string(),
                structured: None,
                cost_usd: Some(0.0),
            })
        }
    }

    #[test]
    fn cap_one_serialises_concurrent_next_step_calls() {
        let runtime = LatencyRuntime {
            latency: Duration::from_millis(50),
            starts: Mutex::new(Vec::new()),
        };
        let gate = Arc::new(ModelGate::new());
        gate.set_cap("test:m", 1);
        let req = AgentToolLoopRequest {
            model: "test:m".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: String::new(),
            prompt: String::new(),
            tools: Vec::new(),
            max_steps: 1,
        };

        std::thread::scope(|scope| {
            for _ in 0..3 {
                let gate = gate.clone();
                let req = req.clone();
                let runtime_ref = &runtime;
                scope.spawn(move || {
                    let gated = GatedRuntime::new(
                        runtime_ref as &dyn AgentRuntime,
                        gate,
                        None,
                        Priority::Normal,
                        "test:m",
                    );
                    gated.next_step_blocking(&req, &[]).unwrap();
                });
            }
        });

        let mut starts = runtime.starts.lock().unwrap().clone();
        starts.sort();
        assert_eq!(starts.len(), 3);
        // Each successive start must be at least latency - tolerance
        // after the previous one. With cap=1 the gate cannot let two
        // calls overlap, so the gap must be >= 50ms (minus a 30ms slack
        // for thread scheduling and Notify wake-up jitter).
        let tolerance = Duration::from_millis(30);
        let min_gap = Duration::from_millis(50) - tolerance;
        let gap_a = starts[1].duration_since(starts[0]);
        let gap_b = starts[2].duration_since(starts[1]);
        assert!(
            gap_a >= min_gap,
            "expected gap_a >= {min_gap:?}, got {gap_a:?}"
        );
        assert!(
            gap_b >= min_gap,
            "expected gap_b >= {min_gap:?}, got {gap_b:?}"
        );
    }

    /// Scripted runtime returning a single `Final` step. The cap-of-2
    /// configuration here lets the test prove that small-fan-out
    /// concurrent calls *do* overlap when the gate has slack — i.e. we
    /// haven't accidentally serialised everything.
    #[test]
    fn cap_two_allows_overlap_for_two_concurrent_steps() {
        let runtime = LatencyRuntime {
            latency: Duration::from_millis(50),
            starts: Mutex::new(Vec::new()),
        };
        let gate = Arc::new(ModelGate::new());
        gate.set_cap("test:m", 2);
        let req = AgentToolLoopRequest {
            model: "test:m".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: String::new(),
            prompt: String::new(),
            tools: Vec::new(),
            max_steps: 1,
        };

        let started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let gate = gate.clone();
                let req = req.clone();
                let runtime_ref = &runtime;
                scope.spawn(move || {
                    let gated = GatedRuntime::new(
                        runtime_ref as &dyn AgentRuntime,
                        gate,
                        None,
                        Priority::Normal,
                        "test:m",
                    );
                    gated.next_step_blocking(&req, &[]).unwrap();
                });
            }
        });
        let elapsed = started.elapsed();

        // Two calls × 50ms each, cap=2, should finish in well under
        // serial 100ms — assert a generous 90ms ceiling.
        assert!(
            elapsed < Duration::from_millis(90),
            "expected overlap with cap=2; got {elapsed:?}"
        );
    }

    /// The tool-loop step in [`AgentRuntime`] returns the inner result
    /// unchanged — even when the gate momentarily holds the permit.
    #[test]
    fn passes_through_inner_next_step_result_verbatim() {
        struct EchoRuntime;
        impl AgentRuntime for EchoRuntime {
            fn triage_finding_blocking(&self, _r: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
            fn supports_tools(&self) -> bool {
                true
            }
            fn next_step_blocking(
                &self,
                _request: &AgentToolLoopRequest,
                _history: &[LoopHistoryEntry],
            ) -> Result<AgentLoopStep> {
                Ok(AgentLoopStep::ToolCall {
                    calls: vec![ToolCall {
                        name: "read_source".to_string(),
                        input: serde_json::json!({"file": "x.c"}),
                        call_id: "c1".to_string(),
                    }],
                })
            }
        }

        let inner = EchoRuntime;
        let gate = Arc::new(ModelGate::new());
        gate.set_cap("test:m", 8);
        let gated = GatedRuntime::new(&inner, gate, None, Priority::Normal, "test:m");
        let req = AgentToolLoopRequest {
            model: "test:m".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: String::new(),
            prompt: String::new(),
            tools: Vec::new(),
            max_steps: 1,
        };

        let step = gated.next_step_blocking(&req, &[]).unwrap();
        match step {
            AgentLoopStep::ToolCall { calls } => {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].name, "read_source");
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }
}
