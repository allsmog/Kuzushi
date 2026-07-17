use super::*;

#[test]
fn privileged_method_denial_matrix_preserves_capability_errors() {
    let grants = Grant::default();
    let invocation = InvocationId("inv".to_string());
    let mut mcp = McpCallRequest {
        invocation_id: invocation.clone(),
        alias: "missing".to_string(),
        tool: "call".to_string(),
        arguments: Value::Null,
        limits: McpCallLimits::default(),
    };
    let fuzz = FuzzRunRequest {
        invocation_id: invocation.clone(),
        engine: FuzzEngine::CargoFuzz,
        target: FuzzTarget {
            language: "rust".to_string(),
            project_path: ".".to_string(),
            harness_path: "harness.rs".to_string(),
        },
        inputs: BTreeMap::new(),
        limits: FuzzLimits::default(),
        sandbox: FuzzSandbox::default(),
    };

    assert_eq!(
        authorize_fs_grant(&grants, FsScope::Workspace, FsPolicyAction::Read).unwrap_err(),
        KwpError::denied("fs")
    );
    assert_eq!(
        authorize_fs_grant(&grants, FsScope::Workspace, FsPolicyAction::Write).unwrap_err(),
        KwpError::denied("fs.write")
    );
    assert_eq!(
        authorize_runtime_grant(&grants).unwrap_err(),
        KwpError::denied("runtime")
    );
    assert_eq!(
        authorize_artifact_grant(&grants).unwrap_err(),
        KwpError::denied("artifacts.write")
    );
    assert_eq!(
        authorize_findings_grant(&grants, 1).unwrap_err(),
        KwpError::denied("findings.create")
    );
    assert_eq!(
        authorize_bus_topic(&grants, "events.test").unwrap_err(),
        KwpError::denied("bus.produce")
    );
    assert_eq!(
        authorize_mcp_grant(&grants, &McpCatalog::default(), &invocation, &mut mcp).unwrap_err(),
        KwpError::denied("mcp")
    );
    assert_eq!(
        authorize_fuzz_grant(&grants, &invocation, &fuzz).unwrap_err(),
        KwpError::denied("fuzz")
    );
}

#[test]
fn path_network_and_audit_rules_remain_fail_closed() {
    assert_eq!(
        validate_fs_path(FsScope::Workspace, ".kuzushi/v3/config.toml").unwrap_err(),
        KwpError::denied("fs.control_path")
    );
    assert_eq!(
        validate_bus_topic("").unwrap_err(),
        KwpError::BadRequest("bus topic omitted".to_string())
    );
    assert_eq!(
        audit_decision::<()>(&Err(KwpError::RuntimeBudget)),
        (
            AuditDecision::Deny,
            serde_json::json!({
                "errorCode": KwpError::RuntimeBudget.code(),
                "error": KwpError::RuntimeBudget.to_string(),
            })
        )
    );
}

#[test]
fn meters_are_scoped_and_preserve_quota_error_names() {
    let grant = McpGrant {
        alias: "one".to_string(),
        tools: vec!["call".to_string()],
        mode: McpGrantMode::Dedicated,
        max_calls_per_invocation: Some(1),
        max_cpu_seconds_per_invocation: Some(1),
        max_bytes_per_invocation: Some(1),
        max_artifacts_bytes_per_invocation: Some(1),
        workspace: McpWorkspaceMode::ReadWrite,
    };
    let request = McpCallRequest {
        invocation_id: InvocationId("inv".to_string()),
        alias: "one".to_string(),
        tool: "call".to_string(),
        arguments: Value::Null,
        limits: McpCallLimits::default(),
    };
    let mut calls = BTreeMap::new();

    reserve_mcp_call(&mut calls, &grant, &request).unwrap();
    assert_eq!(
        reserve_mcp_call(&mut calls, &grant, &request).unwrap_err(),
        KwpError::quota("mcp.calls")
    );
}
