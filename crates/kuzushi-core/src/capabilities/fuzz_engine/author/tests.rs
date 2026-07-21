use super::toolbox::AuthorToolboxConfig;
use super::*;
use crate::runtime::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, LoopHistoryEntry,
    ToolCall, TriageRequest,
};
use crate::spend::Operation;
use anyhow::Result;
use serde_json::json;
use std::path::Path;
use std::sync::Mutex;

/// Scripted next-step runtime (same pattern as the deep-auditor tests):
/// each call pops the next model action, so the loop's tool execution and
/// accounting run for real while the model is deterministic.
struct ScriptedRuntime {
    steps: Mutex<Vec<AgentLoopStep>>,
}

impl ScriptedRuntime {
    fn new(steps: Vec<AgentLoopStep>) -> Self {
        Self {
            steps: Mutex::new(steps),
        }
    }
}

impl AgentRuntime for ScriptedRuntime {
    fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
        unreachable!()
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::findings::TriageOutcome> {
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
        let mut steps = self.steps.lock().unwrap();
        anyhow::ensure!(!steps.is_empty(), "scripted runtime exhausted");
        Ok(steps.remove(0))
    }
}

fn tool_call(name: &str, input: serde_json::Value, cost: f64) -> AgentLoopStep {
    AgentLoopStep::ToolCall {
        call: ToolCall {
            name: name.to_string(),
            input,
            call_id: format!("call-{name}"),
        },
        cost_usd: Some(cost),
    }
}

fn final_step(text: &str, cost: f64) -> AgentLoopStep {
    AgentLoopStep::Final {
        text: text.to_string(),
        structured: None,
        cost_usd: Some(cost),
    }
}

fn fixture_config(root: &Path) -> AuthorConfig {
    AuthorConfig {
        paths: FuzzPaths {
            afe_repo: root.join("afe"),
            python_bin: root.join("afe/.venv/bin/python"),
            workspace_root: root.join("ws"),
            data_root: root.join("ws/data"),
            source_dir: root.join("repo"),
        },
        model: "anthropic:claude-test".to_string(),
        budget_usd: 5.0,
        max_targets: 3,
        max_steps: 8,
        smoke_seconds: 5,
        build_timeout: std::time::Duration::from_secs(30),
    }
}

fn write_workorder(root: &Path, target: &str) {
    let dir = root.join("ws/targets/c").join(target).join(".localfuzz");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("workorder.json"),
        json!({"generator": "direct_call", "sinks_with_context": []}).to_string(),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("repo")).unwrap();
}

#[test]
fn author_session_executes_tools_folds_cost_and_grades_deterministically() {
    let temp = tempfile::tempdir().unwrap();
    let cfg = fixture_config(temp.path());
    write_workorder(temp.path(), "vhdx");
    // Model: read the workorder, write a harness, then claim victory. There
    // is no built fuzzer on disk, so the deterministic verdict must be
    // `failed` regardless of the model's confident final text.
    let runtime = ScriptedRuntime::new(vec![
        tool_call("read_workorder", json!({}), 0.02),
        tool_call("write_harness", json!({"content": "// h\n"}), 0.03),
        final_step("harness written, all good!", 0.01),
    ]);

    let report = run_author(&runtime, None, &cfg, &["vhdx".to_string()], None).unwrap();

    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0];
    assert_eq!(target.verdict, "failed");
    assert!(!target.authored);
    assert_eq!(target.steps_used, 3);
    assert!((target.cost_usd - 0.06).abs() < 1e-9);
    assert!((report.total_cost_usd - 0.06).abs() < 1e-9);
    // The tool really executed: the harness file exists at the contained path.
    assert!(temp
        .path()
        .join("ws/targets/c/vhdx/harness.cpp")
        .is_file());
}

#[test]
fn budget_exhaustion_parks_remaining_targets_without_model_calls() {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = fixture_config(temp.path());
    cfg.budget_usd = 0.05;
    write_workorder(temp.path(), "a");
    write_workorder(temp.path(), "b");
    // First session spends 0.06 (> budget); the second target must be
    // parked as budget-exhausted without touching the runtime again.
    let runtime = ScriptedRuntime::new(vec![
        tool_call("read_workorder", json!({}), 0.05),
        final_step("done", 0.01),
    ]);

    let report =
        run_author(&runtime, None, &cfg, &["a".to_string(), "b".to_string()], None).unwrap();

    assert_eq!(report.targets.len(), 2);
    assert_eq!(report.targets[1].verdict, "budget-exhausted");
    assert!(report.budget_exhausted);
}

#[test]
fn max_targets_bounds_the_session_count() {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = fixture_config(temp.path());
    cfg.max_targets = 1;
    write_workorder(temp.path(), "a");
    write_workorder(temp.path(), "b");
    let runtime = ScriptedRuntime::new(vec![final_step("skip", 0.01)]);

    let report =
        run_author(&runtime, None, &cfg, &["a".to_string(), "b".to_string()], None).unwrap();

    assert_eq!(report.targets.len(), 1);
}

#[test]
fn truncated_loop_without_built_binary_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = fixture_config(temp.path());
    cfg.max_steps = 2;
    write_workorder(temp.path(), "vhdx");
    // The model never finishes inside max_steps; the loop truncates and the
    // verdict stays failed (nothing was built).
    let runtime = ScriptedRuntime::new(vec![
        tool_call("read_workorder", json!({}), 0.01),
        tool_call("read_workorder", json!({}), 0.01),
    ]);

    let report = run_author(&runtime, None, &cfg, &["vhdx".to_string()], None).unwrap();

    assert_eq!(report.targets[0].verdict, "failed");
    assert_eq!(report.targets[0].steps_used, 2);
}

#[test]
fn cancellation_stops_before_the_next_target() {
    let temp = tempfile::tempdir().unwrap();
    let cfg = fixture_config(temp.path());
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let runtime = ScriptedRuntime::new(vec![]);

    let report = run_author(
        &runtime,
        None,
        &cfg,
        &["a".to_string()],
        Some(&cancellation),
    )
    .unwrap();

    assert!(report.targets.is_empty());
}

#[test]
fn spend_tickets_are_deposited_and_settled_at_actual_cost() {
    let temp = tempfile::tempdir().unwrap();
    let cfg = fixture_config(temp.path());
    write_workorder(temp.path(), "vhdx");
    let spend = crate::spend::SpendLimiter::open_in_memory().unwrap();
    spend.set_cap(Operation::FuzzAuthor, 10.0).unwrap();
    let runtime = ScriptedRuntime::new(vec![final_step("done", 0.25)]);

    run_author(&runtime, Some(&spend), &cfg, &["vhdx".to_string()], None).unwrap();

    let spent = spend.total_spent(Operation::FuzzAuthor).unwrap();
    assert!((spent - 0.25).abs() < 1e-9, "settled at actual, got {spent}");
}

#[test]
fn author_prompt_carries_the_workorder_inside_an_untrusted_block() {
    let temp = tempfile::tempdir().unwrap();
    let cfg = fixture_config(temp.path());
    write_workorder(temp.path(), "vhdx");
    let toolbox_cfg = AuthorToolboxConfig {
        paths: cfg.paths.clone(),
        target: "vhdx".to_string(),
        build_timeout: cfg.build_timeout,
        smoke_seconds: cfg.smoke_seconds,
    };

    let request = author_request(&cfg, "vhdx", &toolbox_cfg);

    // The workorder rides inside a decodable untrusted-derived record —
    // armor framing intact, content recoverable.
    let frame = extract_untrusted_frame(&request.prompt);
    let record = crate::prompts::decode_untrusted_record(&frame).unwrap();
    assert_eq!(record.label, "fuzz-authoring-workorder");
    assert!(record.content.contains("direct_call"));
    assert_eq!(request.max_steps, 8);
    assert!(request
        .tools
        .iter()
        .any(|tool| tool.name == "write_harness"));
}

/// Slice the first untrusted record frame out of a prompt: from its begin
/// marker line through its end marker line inclusive.
fn extract_untrusted_frame(prompt: &str) -> String {
    let lines: Vec<&str> = prompt.lines().collect();
    let begin = lines
        .iter()
        .position(|line| line.contains("UNTRUSTED") && line.contains("BEGIN"))
        .expect("prompt carries an untrusted record");
    let end = lines[begin..]
        .iter()
        .position(|line| line.contains("UNTRUSTED") && line.contains("END"))
        .expect("untrusted record has an end marker")
        + begin;
    lines[begin..=end].join("\n")
}
