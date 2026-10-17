use super::*;

const TOOL: &str = "taint-iris-next:codeql-db";

#[test]
fn unbound_repository_preparation_refuses_before_runtime_or_ledger_creation() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let runtime = AccountingRuntime::default();
    let result = bind_runtime(
        registry.resolve_tool(TOOL).unwrap(),
        &json!({}),
        &ctx,
        Some(&runtime),
    );
    assert!(
        result.is_err(),
        "Model-backed repository preparation bypassed investigation allowance admission"
    );
    assert_allowance_refused(result.err().unwrap());
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert!(!workspace.findings_db_path().exists());
}

#[test]
fn model_preparation_is_auxiliary_labs_map_with_separate_execution_consent() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let tool = registry.resolve_tool(TOOL).unwrap();
    assert_eq!(tool.phase, ToolPhase::Map);
    assert!(!tool.phase_result);
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Context));
    assert_eq!(tool.effect, ToolEffect::RepositoryExecute);
    assert_eq!(tool.approval, ApprovalPolicy::Explicit);
    assert!(tool
        .options
        .iter()
        .any(|option| option.name == "allowanceRef"));
    assert!(tool.hidden);
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::Always);
    let deterministic = registry.resolve_tool("codeql:create-db").unwrap();
    assert_eq!(deterministic.runtime_requirement, RuntimeRequirement::Never);
    assert_eq!(deterministic.effect, ToolEffect::RepositoryExecute);
    assert_eq!(deterministic.approval, ApprovalPolicy::Explicit);
}

#[test]
fn only_explicitly_categorized_repository_execution_opts_into_allowance() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let mut tool = registry.resolve_tool(TOOL).unwrap().clone();
    tool.allowance_category = Some(AllowanceCategory::Context);
    assert!(supports_allowance(&tool));
    tool.allowance_category = None;
    assert!(!supports_allowance(&tool));
    assert_eq!(tool.effect, ToolEffect::RepositoryExecute);
    assert_eq!(tool.approval, ApprovalPolicy::Explicit);
}

#[test]
fn repository_preparation_cannot_borrow_protected_review() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = bound_runtime(&ctx, &AccountingRuntime::default());
    let mut work = runtime.binding.as_ref().unwrap().work().clone();
    work.work = InvestigationWork::Review;
    let runtime = AccountingRuntime {
        binding: Some(AllowanceBinding::new(open_ledger(&ctx).unwrap(), work).unwrap()),
        ..runtime
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let error = bind_runtime(
        registry.resolve_tool(TOOL).unwrap(),
        &json!({}),
        &ctx,
        Some(&runtime),
    )
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("parent Review allowance"),
        "{error:#}"
    );
    assert_allowance_refused(error);
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(
        (
            snapshot.committed_calls,
            snapshot.review_calls,
            snapshot.protected_review_remaining()
        ),
        (0, 0, 1)
    );
}

#[test]
fn declared_context_calls_reserve_and_stop_before_protected_capacity() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let original = AccountingRuntime::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"study","revision":1,"workId":"pass-1"}});
    let runtime = bind_runtime(
        registry.resolve_tool(TOOL).unwrap(),
        &input,
        &ctx,
        Some(&original),
    )
    .unwrap()
    .unwrap();
    for _ in 0..2 {
        runtime
            .query_blocking(admission_request(&workspace, "No repository execution"))
            .unwrap();
    }
    assert!(runtime
        .query_blocking(admission_request(
            &workspace,
            "Must refuse before transport"
        ))
        .is_err());
    assert_eq!(original.calls.load(Ordering::SeqCst), 2);
    let ledger = open_ledger(&ctx).unwrap();
    let snapshot = ledger.allowance_snapshot("study").unwrap();
    assert_eq!(
        (
            snapshot.committed_calls,
            snapshot.review_calls,
            snapshot.protected_review_remaining()
        ),
        (2, 0, 1)
    );
    assert!(!workspace.state_dir().join("codeql-db").exists());
}

fn admission_request(workspace: &WorkspaceTarget, prompt: &str) -> AgentQueryRequest {
    AgentQueryRequest::new(MODEL, workspace.root(), "Owned admission check", prompt)
}

fn source_repository(root: &std::path::Path) {
    std::fs::write(root.join("owned.py"), "# Owned metadata. Never executed.\n").unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "-f", "--", "owned.py"],
        vec!["commit", "-qm", "fixture source"],
    ] {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "user.name=Owned Fixture",
                "-c",
                "user.email=fixture@example.invalid",
            ])
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn execution_consent_does_not_substitute_for_a_call_allowance() {
    let (root, workspace, config) = fixture();
    source_repository(root.path());
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let runtime = AccountingRuntime::default();
    let prepared = registry
        .prepare_dispatch_input(TOOL, json!({}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("needs an approved investigation allowance"),
        "{error:#}"
    );
    assert_allowance_refused(error);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert!(!workspace.state_dir().join("codeql-db").exists());
}

#[test]
fn approved_call_capacity_does_not_authorize_repository_execution() {
    let (root, workspace, config) = fixture();
    source_repository(root.path());
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let runtime = AccountingRuntime::default();
    let input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"study","revision":1,"workId":"pass-1"}});
    let prepared = registry
        .prepare_dispatch_input(TOOL, input, &ctx, None)
        .unwrap();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("requires explicit operator authorization"),
        "{error:#}"
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!((snapshot.committed_calls, snapshot.review_calls), (0, 0));
    assert!(!workspace.state_dir().join("codeql-db").exists());
    assert!(!root.path().join(".git/worktrees").exists());
}

#[test]
fn accepted_discovery_membership_is_not_silently_used_for_database_preparation() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let error = registry
        .prepare_tool_input(TOOL, json!({"scanScopeRef":{"scopeId":"owned"}}), None)
        .unwrap_err();
    assert!(error.to_string().contains("unknown option"), "{error:#}");
    assert!(registry
        .resolve_tool(TOOL)
        .unwrap()
        .description
        .contains("whole bound target"));
}
