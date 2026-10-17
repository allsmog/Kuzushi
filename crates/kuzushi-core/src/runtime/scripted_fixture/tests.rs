use super::*;
use crate::runtime::{run_tool_loop, ToolCall, ToolResult};
use crate::{Finding, Severity, TriageOutcome, V2Config, WorkspaceTarget};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct ScriptedRuntime {
    calls: AtomicUsize,
    fail: bool,
    tools: bool,
    refuse_preflight: bool,
}

impl AgentRuntime for ScriptedRuntime {
    fn preflight_model_blocking(&self, _: &str) -> Result<()> {
        anyhow::ensure!(!self.refuse_preflight, "scripted model preflight refused");
        Ok(())
    }

    fn preflight_tool_loop_blocking(&self, _: &AgentToolLoopRequest) -> Result<()> {
        anyhow::ensure!(!self.refuse_preflight, "scripted loop preflight refused");
        Ok(())
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(!self.fail, "scripted review failure");
        Ok(TriageOutcome {
            cost_usd: 0.01,
            cost_usd_exact: false,
            estimated_cost_usd: Some(0.02),
            ..Default::default()
        })
    }

    fn supports_tools(&self) -> bool {
        self.tools
    }

    fn next_step_blocking(
        &self,
        _: &AgentToolLoopRequest,
        _: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(!self.fail, "scripted turn failure");
        if index == 0 {
            return Ok(AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "inert_context".into(),
                    input: json!({}),
                    call_id: "scripted-call".into(),
                },
                cost_usd: Some(0.01),
            });
        }
        Ok(AgentLoopStep::Final {
            text: "Scripted review complete".into(),
            structured: None,
            cost_usd: None,
        })
    }
}

fn with_context(test: impl FnOnce(&ToolExecutionContext<'_>)) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai:scripted-review".into()),
        ..Default::default()
    };
    test(&ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    });
}

fn triage_request(ctx: &ToolExecutionContext<'_>) -> TriageRequest {
    TriageRequest {
        model: ctx.config.model.clone().unwrap(),
        cwd: ctx.workspace.unwrap().root().into(),
        finding: Finding::new_tool(
            "scripted",
            "owned.review",
            "lib.rs",
            1,
            None,
            Severity::Low,
            "Owned inert claim",
        ),
        prompt_template: None,
    }
}

fn loop_request(ctx: &ToolExecutionContext<'_>) -> AgentToolLoopRequest {
    AgentToolLoopRequest {
        model: ctx.config.model.clone().unwrap(),
        cwd: ctx.workspace.unwrap().root().into(),
        system_prompt: "Owned scripted review; no provider transport".into(),
        prompt: "Return an inert context marker and finish".into(),
        tools: vec![crate::runtime::AgentTool {
            name: "inert_context".into(),
            description: "Pure fixture marker, no source execution".into(),
            input_schema: json!({"type":"object"}),
        }],
        max_steps: 2,
        runtime_options: None,
        temperature: None,
    }
}

fn receipt(
    ctx: &ToolExecutionContext<'_>,
    runtime: &AccountedScriptedRuntime<'_>,
) -> crate::allowance::AllowanceSnapshot {
    SpendLimiter::open(ctx.workspace.unwrap().findings_db_path())
        .unwrap()
        .allowance_snapshot(&runtime.binding.work().investigation_id)
        .unwrap()
}

fn inert_tool(call: &ToolCall) -> Result<ToolResult> {
    Ok(ToolResult {
        call_id: call.call_id.clone(),
        output: json!({"fixture":"owned inert marker"}),
        is_error: false,
    })
}

#[test]
fn triage_settles_its_incomplete_cost_and_stops_before_an_extra_request() {
    with_context(|ctx| {
        let inner = ScriptedRuntime::default();
        let runtime = account_scripted_runtime(ctx, &inner, InvestigationWork::Review, 1);
        let outcome = runtime
            .triage_finding_blocking(triage_request(ctx))
            .unwrap();
        assert_eq!(outcome.estimated_cost_usd, Some(0.02));
        assert!(runtime
            .triage_finding_blocking(triage_request(ctx))
            .is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        let receipt = receipt(ctx, &runtime);
        assert_eq!(receipt.committed_calls, 1);
        assert_eq!(receipt.unresolved_calls, 0);
        assert!(!receipt.cost.is_complete());
        assert_eq!(receipt.cost.observed_usd(), 0.01);
    });
}

#[test]
fn every_tool_loop_turn_reserves_and_settles_before_the_limit() {
    with_context(|ctx| {
        let inner = ScriptedRuntime {
            tools: true,
            ..Default::default()
        };
        let runtime = account_scripted_runtime(ctx, &inner, InvestigationWork::Review, 2);
        let request = loop_request(ctx);
        let outcome = run_tool_loop(&runtime, &request, &mut inert_tool).unwrap();
        assert_eq!(outcome.steps_used, 2);
        assert!(!outcome.truncated);
        assert!(!outcome.cost_usd_exact);
        assert!(runtime.next_step_blocking(&request, &[]).is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        let receipt = receipt(ctx, &runtime);
        assert_eq!(receipt.committed_calls, 2);
        assert_eq!(receipt.unresolved_calls, 0);
        assert!(!receipt.cost.is_complete());
        assert_eq!(receipt.cost.observed_usd(), 0.01);
    });
}

#[test]
fn failed_triage_keeps_a_consumed_unresolved_reservation() {
    with_context(|ctx| {
        let inner = ScriptedRuntime {
            fail: true,
            ..Default::default()
        };
        let runtime = account_scripted_runtime(ctx, &inner, InvestigationWork::Review, 1);
        assert!(runtime
            .triage_finding_blocking(triage_request(ctx))
            .is_err());
        assert!(runtime
            .triage_finding_blocking(triage_request(ctx))
            .is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipt(ctx, &runtime).committed_calls, 1);
        assert_eq!(receipt(ctx, &runtime).unresolved_calls, 1);
    });
}

#[test]
fn failed_tool_turn_keeps_a_consumed_unresolved_reservation() {
    with_context(|ctx| {
        let inner = ScriptedRuntime {
            fail: true,
            tools: true,
            ..Default::default()
        };
        let runtime = account_scripted_runtime(ctx, &inner, InvestigationWork::Review, 1);
        let request = loop_request(ctx);
        assert!(run_tool_loop(&runtime, &request, &mut inert_tool).is_err());
        assert!(runtime.next_step_blocking(&request, &[]).is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipt(ctx, &runtime).committed_calls, 1);
        assert_eq!(receipt(ctx, &runtime).unresolved_calls, 1);
    });
}

#[test]
fn model_changes_fail_before_triage_or_a_tool_turn_is_reserved() {
    with_context(|ctx| {
        let inner = ScriptedRuntime {
            tools: true,
            ..Default::default()
        };
        let runtime = account_scripted_runtime(ctx, &inner, InvestigationWork::Review, 2);
        let mut triage = triage_request(ctx);
        triage.model = "openai:unapproved-scripted-model".into();
        assert!(runtime.triage_finding_blocking(triage).is_err());
        let mut request = loop_request(ctx);
        request.model = "openai:unapproved-scripted-model".into();
        assert!(run_tool_loop(&runtime, &request, &mut inert_tool).is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        assert_eq!(receipt(ctx, &runtime).committed_calls, 0);
    });
}

#[test]
fn preflight_refusals_and_missing_tool_support_are_forwarded_without_calls() {
    with_context(|ctx| {
        let inner = ScriptedRuntime {
            refuse_preflight: true,
            ..Default::default()
        };
        let runtime = account_scripted_runtime(ctx, &inner, InvestigationWork::Review, 1);
        let request = loop_request(ctx);
        assert!(runtime.preflight_model_blocking(&request.model).is_err());
        assert!(runtime.preflight_tool_loop_blocking(&request).is_err());
        assert!(!runtime.supports_tools());
        assert!(run_tool_loop(&runtime, &request, &mut inert_tool).is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        assert_eq!(receipt(ctx, &runtime).committed_calls, 0);
    });
}
