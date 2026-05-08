use super::*;

impl ShellApp {
    pub(crate) fn start_background_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
    ) {
        self.start_background_tool_with_activity(
            tool_name,
            input,
            workspace,
            status,
            thinking_level,
            None,
        );
    }

    pub(crate) fn start_background_tool_with_activity(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        activity: Option<LiveActivity>,
    ) {
        if let Some(active) = self.tool_running.as_deref() {
            self.log(
                "tool",
                format!(
                    "{active} is still running; wait for its result before starting {tool_name}"
                ),
            );
            return;
        }

        let registry = self.registry.clone();
        let config = self.config.clone();
        let target = workspace.root().to_path_buf();
        let run_id = new_run_id("tool");
        let target_label = target.display().to_string();
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some(tool_name.clone()),
            target_label.clone(),
        );
        let _ = write_run_summary(&target, &summary);
        let _ = append_run_trace_step(
            &target,
            &run_id,
            &RunTraceStep::new(1, "tool", format!("{tool_name} started")),
        );
        let (tx, rx) = mpsc::channel();
        self.target = Some(target.clone());
        self.tool_rx = Some(rx);
        self.tool_running = Some(tool_name.clone());
        self.tool_run_id = Some(run_id.clone());
        self.tool_abort_requested = false;
        self.log(
            "tool",
            format!(
                "running {tool_name} in background; {status} under {target_label} · run {run_id}"
            ),
        );
        self.set_live_activity(
            activity.unwrap_or_else(|| live_activity_for_tool(&tool_name, status)),
        );

        thread::spawn(move || {
            background_tool_worker(
                registry,
                config,
                workspace,
                tool_name,
                input,
                thinking_level,
                tx,
            )
        });
    }
}
