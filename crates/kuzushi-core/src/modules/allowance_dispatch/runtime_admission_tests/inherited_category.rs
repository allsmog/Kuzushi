use super::*;

fn with_work(ctx: &ToolExecutionContext<'_>, work: InvestigationWork) -> AccountingRuntime {
    let runtime = bound_runtime(ctx, &AccountingRuntime::default());
    let mut identity = runtime.binding.as_ref().unwrap().work().clone();
    identity.work = work;
    AccountingRuntime {
        binding: Some(AllowanceBinding::new(open_ledger(ctx).unwrap(), identity).unwrap()),
        ..runtime
    }
}

#[test]
fn inherited_review_cannot_fund_non_review_child_dispatch() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = with_work(&ctx, InvestigationWork::Review);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    for (name, input) in [
        ("context:build", json!({"enrichment":true})),
        ("threat-model:build", json!({})),
        ("systems-hunt:systems-invariant-extract", json!({})),
        ("variant:lift-pattern", json!({})),
    ] {
        let descriptor = registry.resolve_tool(name).unwrap();
        let result = bind_runtime(descriptor, &input, &ctx, Some(&runtime));
        assert!(
            result.is_err(),
            "{name} reused Review accounting for {:?}",
            descriptor_work(descriptor)
        );
        let error = result.err().unwrap();
        assert_allowance_refused(error);
    }
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
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_context_dispatch_refuses_parent_review_before_collection_or_query() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = with_work(&ctx, InvestigationWork::Review);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input("context:build", json!({"enrichment":true}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("parent Review allowance"),
        "{error:#}"
    );
    assert_allowance_refused(error);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!((snapshot.committed_calls, snapshot.review_calls), (0, 0));
}

#[test]
fn same_work_is_reused_and_mismatches_in_both_directions_are_refused() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let mut tool = registry.resolve_tool("context:build").unwrap().clone();
    for category in [
        AllowanceCategory::Context,
        AllowanceCategory::Scope,
        AllowanceCategory::Discovery,
        AllowanceCategory::Review,
        AllowanceCategory::Report,
        AllowanceCategory::Learning,
    ] {
        tool.allowance_category = Some(category);
        let expected = descriptor_work(&tool).unwrap();
        for actual in [
            InvestigationWork::Context,
            InvestigationWork::Scope,
            InvestigationWork::Discovery,
            InvestigationWork::Review,
            InvestigationWork::Report,
            InvestigationWork::Learning,
        ] {
            for effect in [ToolEffect::Read, ToolEffect::WorkspaceWrite] {
                tool.effect = effect;
                let runtime = with_work(&ctx, actual);
                let outcome =
                    bind_runtime(&tool, &json!({"enrichment":true}), &ctx, Some(&runtime));
                assert_eq!(
                    outcome.is_ok(),
                    expected == actual,
                    "{expected:?} child, {actual:?} parent, {effect:?}"
                );
                assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
            }
        }
    }
}

#[test]
fn deterministic_work_does_not_reclassify_or_consume_the_parent_allowance() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = with_work(&ctx, InvestigationWork::Review);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input("context:build", json!({"enrichment":false}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap();
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!((snapshot.committed_calls, snapshot.review_calls), (0, 0));
    assert_eq!(
        runtime.binding.as_ref().unwrap().work().work,
        InvestigationWork::Review
    );
}
