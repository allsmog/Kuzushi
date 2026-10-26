use super::*;
mod failure;
mod recovery;

fn scope_target() -> (
    tempfile::TempDir,
    WorkspaceTarget,
    V2Config,
    crate::workspace::ScanScopeProposalRef,
) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.py"),
        "print('labeled scope study')\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let review =
        crate::workspace::create_scan_scope_proposal(&context(&workspace, &config), None).unwrap();
    (root, workspace, config, review.reference)
}

fn scope_plan(reference: &crate::workspace::ScanScopeProposalRef) -> Value {
    json!({"campaignId":"scope-draft","investigationId":"investigation",
        "generationTool":"pack:suggest-scopes","contextInput":{"proposalRef":reference}})
}

#[test]
fn scope_study_freezes_one_job_and_approval_binds_exact_inputs_without_spending() {
    let (root, workspace, config, reference) = scope_target();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let output = registry
        .execute_tool("campaign:context-study", scope_plan(&reference), &ctx)
        .unwrap();
    let receipt = load_context_study(root.path(), "scope-draft").unwrap();
    assert_eq!(output["data"]["generationTool"], "pack:suggest-scopes");
    assert_eq!(receipt.generation_tool, "pack:suggest-scopes");
    assert_eq!(receipt.job_count(), 1);
    assert!(receipt.preparation_jobs.is_empty());
    assert!(receipt.input.get("allowanceRef").is_none());
    assert!(receipt.input["threatModelRef"].is_null());
    assert_eq!(receipt.input["maxOutputTokens"], 4096);
    let document = read_bounded_plan(root.path(), "scope-draft").unwrap();
    assert_eq!(document["jobs"][0]["tool"], "pack:suggest-scopes");
    let approved = approve(&registry, &ctx, approval(&receipt)).unwrap();
    let snapshot: crate::allowance::AllowanceSnapshot =
        serde_json::from_value(approved["data"]["allowance"].clone()).unwrap();
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(
        snapshot.work_plan.as_ref().unwrap().jobs[0].tool,
        "pack:suggest-scopes"
    );
    let bound = receipt.bound_input(&snapshot).unwrap();
    assert_eq!(bound["allowanceRef"]["workId"], "scope-draft:context-001");
    assert!(registry
        .prepare_dispatch_input("pack:suggest-scopes", bound, &ctx, None)
        .is_ok());
    assert!(receipt.generated_scopes(root.path()).unwrap().is_none());
    assert!(receipt.generated_context(root.path()).is_err());
    assert!(!campaign_queue_path(root.path(), "scope-draft").exists());
}

#[test]
fn scope_study_rejects_prep_work_input_allowances_and_changed_scope_heads() {
    for mutation in ["preparation", "allowance", "stale"] {
        let (root, workspace, config, reference) = scope_target();
        let ctx = context(&workspace, &config);
        let registry = ModuleRegistry::with_v2_builtins();
        let mut input = scope_plan(&reference);
        match mutation {
            "preparation" => {
                input["preparationJobs"] = json!([{"tool":"context:build","input":{}}])
            }
            "allowance" => input["contextInput"]["allowanceRef"] = json!({}),
            _ => {
                crate::workspace::edit_scan_scope_proposal(
                    &ctx,
                    &reference,
                    crate::workspace::ScanScopeEdit::WholeRepository,
                )
                .unwrap();
            }
        }
        assert!(registry
            .execute_tool("campaign:context-study", input, &ctx)
            .is_err());
        assert!(!campaign_plan_path(root.path(), "scope-draft").exists());
    }
}

#[test]
fn explicit_scope_context_omission_never_reads_global_context_or_map_history() {
    let (_root, workspace, config, reference) = scope_target();
    let state = workspace.state_dir().join("workflow");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("phase-attempts.jsonl"), "broken Map history\n").unwrap();
    let input = scope_proposal_study_input(
        workspace.root(),
        reference,
        "Optional priorities".into(),
        true,
    )
    .unwrap();
    assert!(input["threatModelRef"].is_null());
    let reference: crate::workspace::ScanScopeProposalRef =
        serde_json::from_value(input["proposalRef"].clone()).unwrap();
    assert!(scope_proposal_study_input(workspace.root(), reference, "".into(), false).is_err());
    let _ = config;
}

#[test]
fn scope_retention_alias_false_is_preserved_before_the_new_plan_is_frozen() {
    let (root, workspace, config, reference) = scope_target();
    let mut input = scope_plan(&reference);
    input["contextInput"]["save_rejected_output"] = json!(false);
    ModuleRegistry::with_v2_builtins()
        .execute_tool(
            "campaign:context-study",
            input,
            &context(&workspace, &config),
        )
        .unwrap();
    let receipt = load_context_study(root.path(), "scope-draft").unwrap();
    assert_eq!(receipt.input["saveRejectedOutput"], false);
    assert!(receipt.input.get("save_rejected_output").is_none());
}
