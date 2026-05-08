use super::*;

pub(in crate::modules) fn run_pipeline_task_selector(
    input: Value,
    _ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let requested = string_array_or_csv_input(&input, &["tasks", "taskIds", "task_ids"])
        .unwrap_or_else(|| {
            vec![
                "semgrep".to_string(),
                "dep-hygiene".to_string(),
                "secret-scan".to_string(),
                "iac-scan".to_string(),
            ]
        });
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
    Ok(json!({
        "ok": true,
        "output": format!("pipeline:task-selector selected {} task{}", selected.len(), if selected.len() == 1 { "" } else { "s" }),
        "data": {
            "tasks": selected,
            "disabledTasks": disabled,
        },
    }))
}

pub(in crate::modules) fn run_pipeline_approval_gate(input: Value) -> Result<Value> {
    let approved = read_bool_any(&input, &["approved", "approve"])?.unwrap_or(true);
    Ok(json!({
        "ok": approved,
        "output": if approved {
            "pipeline:approval-before-verification approved"
        } else {
            "pipeline:approval-before-verification denied"
        },
        "data": {
            "approved": approved,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::modules::ModuleRegistry;
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    #[test]
    fn hidden_pipeline_nodes_dispatch_without_visibility() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

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
        let approval = registry
            .execute_tool(
                "pipeline:approval-before-verification",
                json!({"approved": false}),
                &ctx,
            )
            .unwrap();
        assert_eq!(approval.get("ok").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn approval_gate_defaults_to_approved() {
        let approval = run_pipeline_approval_gate(Value::Null).unwrap();

        assert_eq!(approval.get("ok").and_then(Value::as_bool), Some(true));
    }
}
