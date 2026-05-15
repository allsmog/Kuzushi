use super::*;
use kuzushi_core::run_artifacts::{
    load_run_summary, output_with_run_fallback_context, FailureToLlmContext,
};
use std::path::{Path, PathBuf};

struct ToolEventState {
    abort_requested: bool,
    run_id: Option<String>,
    target: Option<PathBuf>,
}

impl ShellApp {
    pub(crate) fn apply_tool_event(&mut self, event: ToolEvent) {
        let state = self.take_tool_event_state();
        match event {
            ToolEvent::Finished { tool_name, result } => {
                self.apply_finished_tool_event(state, tool_name, result);
            }
            ToolEvent::Failed { tool_name, error } => {
                self.apply_failed_tool_event(state, tool_name, error);
            }
        }
    }

    fn take_tool_event_state(&mut self) -> ToolEventState {
        let state = ToolEventState {
            abort_requested: self.tool_abort_requested,
            run_id: self.tool_run_id.take(),
            target: self.target.clone(),
        };
        self.tool_running = None;
        self.tool_abort_requested = false;
        state
    }

    fn apply_finished_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) {
        let failure_context = record_tool_run_complete(
            state.target.as_deref(),
            state.run_id.as_deref(),
            &tool_name,
            &result,
        );
        let result =
            result_with_fallback_context(state.target.as_deref(), state.run_id.as_deref(), result);
        if state.abort_requested {
            self.log(
                "tool",
                format!("{tool_name} completed after abort request; applying completed result"),
            );
        }
        self.apply_tool_result(&tool_name, result);
        self.log_failure_context(failure_context);
        self.set_completed_activity(tool_name.clone(), "tool result applied");
        self.advance_chain_after_tool(&tool_name);
    }

    fn apply_failed_tool_event(&mut self, state: ToolEventState, tool_name: String, error: String) {
        let failure_context = record_tool_run_failed(
            state.target.as_deref(),
            state.run_id.as_deref(),
            &tool_name,
            &error,
        );
        let result = failed_tool_result(
            state.target.as_deref(),
            state.run_id.as_deref(),
            &tool_name,
            &error,
        );
        self.apply_tool_result(&tool_name, result);
        self.log_tool_failure(
            &tool_name,
            with_next_step(error, "tools, options <tool>, or model <n>"),
            state.abort_requested,
        );
        self.set_refused_activity(
            tool_name.clone(),
            "tool failed before producing a usable result",
        );
        self.log_failure_context(failure_context);
        self.abort_pending_chain(&tool_name);
    }

    fn log_tool_failure(&mut self, tool_name: &str, message: String, abort_requested: bool) {
        if abort_requested {
            self.log(
                "error",
                format!("{tool_name} ended after abort request: {message}"),
            );
        } else {
            self.log("error", message);
        }
    }

    fn log_failure_context(&mut self, context: Option<FailureToLlmContext>) {
        if let Some(context) = context {
            self.log("failure-context", render_failure_context(&context));
            self.set_pending_failure_context(context);
        }
    }

    pub(crate) fn apply_tool_result(&mut self, tool_name: &str, result: serde_json::Value) {
        if let Some(cost_usd) = extract_cost_usd(&result) {
            self.record_cost(cost_usd);
        }
        if matches!(tool_name, "context:build" | "context-lite:index") {
            let _ = self.refresh_context_view();
        }
        self.cache_tool_snapshot(tool_name, &result);
        let rendered = result
            .get("output")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
            });
        self.log("result", rendered);
    }
}

fn result_with_fallback_context(
    target: Option<&Path>,
    run_id: Option<&str>,
    result: serde_json::Value,
) -> serde_json::Value {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return result;
    };
    output_with_run_fallback_context(target, run_id, result)
}

fn failed_tool_result(
    target: Option<&Path>,
    run_id: Option<&str>,
    tool_name: &str,
    error: &str,
) -> serde_json::Value {
    let result = serde_json::json!({
        "ok": false,
        "status": "failed",
        "summary": format!("{tool_name} failed"),
        "artifacts": failed_tool_artifacts(target, run_id),
        "warnings": [],
        "errors": [error],
    });
    result_with_fallback_context(target, run_id, result)
}

fn failed_tool_artifacts(target: Option<&Path>, run_id: Option<&str>) -> serde_json::Value {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return serde_json::json!([]);
    };
    load_run_summary(target, run_id)
        .ok()
        .and_then(|summary| serde_json::to_value(summary.artifacts).ok())
        .unwrap_or_else(|| serde_json::json!([]))
}
