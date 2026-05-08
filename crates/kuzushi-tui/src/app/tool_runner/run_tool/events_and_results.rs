use super::*;

impl ShellApp {
    pub(crate) fn apply_tool_event(&mut self, event: ToolEvent) {
        let abort_requested = self.tool_abort_requested;
        let run_id = self.tool_run_id.take();
        let target = self.target.clone();
        self.tool_running = None;
        self.tool_abort_requested = false;
        match event {
            ToolEvent::Finished { tool_name, result } => {
                record_tool_run_complete(target.as_deref(), run_id.as_deref(), &tool_name, &result);
                if abort_requested {
                    self.log(
                        "tool",
                        format!(
                            "{tool_name} completed after abort request; applying completed result"
                        ),
                    );
                }
                self.apply_tool_result(&tool_name, result);
            }
            ToolEvent::Failed { tool_name, error } => {
                record_tool_run_failed(target.as_deref(), run_id.as_deref(), &tool_name, &error);
                let message = with_next_step(error, "tools, options <tool>, or model <n>");
                if abort_requested {
                    self.log(
                        "error",
                        format!("{tool_name} ended after abort request: {message}"),
                    );
                } else {
                    self.log("error", message);
                }
            }
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
