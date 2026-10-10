use super::*;

#[test]
fn guided_context_requires_an_explicit_choice_and_matching_frozen_goal() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned inert context fixture\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let first = save_brief(
        root.path(),
        "repository",
        0,
        "Prioritize owner questions\n東京 remains exact.",
        &|| false,
    )
    .unwrap();
    let base = json!({"campaignId":"guided-context","investigationId":"owned","contextInput":{},"briefRef":first.reference});
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("briefRef");
    missing["useBriefGuidance"] = json!(true);
    assert!(registry
        .execute_tool("campaign:context-study", missing, &ctx)
        .is_err());
    let mut hidden = base.clone();
    hidden["contextInput"]["operatorBriefRef"] = json!(first.reference);
    assert!(registry
        .execute_tool("campaign:context-study", hidden, &ctx)
        .is_err());
    let mut guided = base.clone();
    guided["useBriefGuidance"] = json!(true);
    let result = registry
        .execute_tool("campaign:context-study", guided, &ctx)
        .unwrap();
    assert_eq!(
        result["data"]["briefGuidance"]["reference"],
        json!(first.reference)
    );
    assert_eq!(result["data"]["briefGuidance"]["text"], first.document.text);
    let receipt = super::super::super::load_context_study(root.path(), "guided-context").unwrap();
    assert_eq!(receipt.input["operatorBriefRef"], json!(first.reference));
    assert_eq!(receipt.job_count(), 1);
    save_brief(root.path(), "repository", 1, "Later goal", &|| false).unwrap();
    assert_eq!(
        super::super::super::load_context_study(root.path(), "guided-context").unwrap(),
        receipt
    );
    let mut plan =
        super::super::super::approved_work::read_bounded_plan(root.path(), "guided-context")
            .unwrap();
    plan["jobs"][0]["input"]["operatorBriefRef"]["revision"] = json!(2);
    assert!(super::super::validate_plan(root.path(), &plan).is_err());
    let mut unguided = base;
    unguided["campaignId"] = json!("unguided-context");
    let result = registry
        .execute_tool("campaign:context-study", unguided, &ctx)
        .unwrap();
    assert!(result["data"].get("briefGuidance").is_none());
    assert!(result["data"]["input"].get("operatorBriefRef").is_none());
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/guided-context/queue.json")
        .exists());
}
