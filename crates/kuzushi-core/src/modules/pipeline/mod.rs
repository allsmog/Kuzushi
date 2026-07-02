use super::*;

pub(in crate::modules) fn run_pipeline_task_selector(
    input: Value,
    _ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let requested = string_array_or_csv_input(&input, &["tasks", "taskIds", "task_ids"])
        .unwrap_or_else(default_native_sast_tasks);
    let disabled =
        string_array_or_csv_input(&input, &["disabledTasks", "disabled_tasks"]).unwrap_or_default();
    let selected = requested
        .into_iter()
        .filter(|task| {
            !disabled
                .iter()
                .any(|disabled| same_scan_task(task, disabled))
        })
        .collect::<Vec<_>>();
    let summary = format!(
        "pipeline:task-selector selected {} task{}",
        selected.len(),
        if selected.len() == 1 { "" } else { "s" }
    );
    let data = json!({
        "tasks": selected,
        "disabledTasks": disabled,
    });
    Ok(crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        data,
    ))
}

pub(in crate::modules) fn run_pipeline_approval_gate(input: Value) -> Result<Value> {
    let approved = read_bool_any(&input, &["approved", "approve"])?.unwrap_or(true);
    if approved {
        return Ok(crate::module_result::completed_output_result(
            "pipeline:approval-before-verification approved",
            "pipeline:approval-before-verification approved",
            json!({ "approved": true }),
        ));
    }
    Ok(crate::module_result::failed_output_result(
        "pipeline:approval-before-verification denied",
        "pipeline:approval-before-verification denied",
        json!({ "approved": false, "reason": "approval-denied" }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::modules::ModuleRegistry;
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    fn pipeline_test_context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        }
    }

    #[test]
    fn hidden_pipeline_nodes_dispatch_without_visibility() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = pipeline_test_context(&config, &workspace);

        assert!(!registry
            .modules()
            .any(|registered_module| registered_module.metadata().id == "pipeline"));
        let selector = registry
            .execute_tool(
                "pipeline:task-selector",
                json!({"tasks": ["semgrep", "secret-scan"], "disabledTasks": ["semgrep"]}),
                &ctx,
            )
            .unwrap();
        assert_eq!(
            selector.pointer("/data/tasks/0").and_then(Value::as_str),
            Some("secret-scan")
        );
        assert_eq!(
            selector.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        let approval = registry
            .execute_tool(
                "pipeline:approval-before-verification",
                json!({"approved": false}),
                &ctx,
            )
            .unwrap();
        assert_eq!(approval.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            approval.pointer("/status").and_then(Value::as_str),
            Some("failed")
        );
    }

    #[test]
    fn approval_gate_defaults_to_approved() {
        let approval = run_pipeline_approval_gate(Value::Null).unwrap();

        assert_eq!(approval.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            approval.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
    }

    #[test]
    fn task_selector_keeps_cargo_audit_in_auto_defaults() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = pipeline_test_context(&config, &workspace);
        let selector =
            run_pipeline_task_selector(json!({"disabledTasks": ["semgrep"]}), &ctx).unwrap();
        let tasks = selector
            .pointer("/data/tasks")
            .and_then(Value::as_array)
            .unwrap();

        assert!(tasks.iter().any(|task| task == "cargo-audit"));
        assert!(!tasks.iter().any(|task| task == "semgrep"));
    }
}
