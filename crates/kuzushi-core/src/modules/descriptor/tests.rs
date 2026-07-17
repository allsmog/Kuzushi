#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn builds_visible_and_hidden_modules() {
        let visible = builtin_module(
            "demo",
            "Demo",
            ModuleKind::Defense,
            "Visible module",
            vec![tool("demo:run", "Run demo.")],
            vec![dag("demo:run", "findings", &["context:build"])],
        );
        assert_eq!(visible.metadata().id, "demo");
        assert!(!visible.is_hidden());
        assert_eq!(visible.tools()[0].name, "demo:run");
        assert!(!visible.tools()[0].hidden);
        assert_eq!(visible.dag_nodes()[0].depends_on, vec!["context:build"]);

        let hidden = hidden_module(
            "internal-demo",
            "Internal Demo",
            ModuleKind::Internal,
            "Hidden module",
            vec![],
            vec![],
        );
        assert!(hidden.is_hidden());

        let deferred = builtin_module(
            "deferred-demo",
            "Deferred Demo",
            ModuleKind::Offense,
            "Opt-in compatibility module",
            vec![tool("deferred-demo:run", "Run deferred demo.")],
            vec![dag("deferred-demo:run", "findings", &["context:build"])],
        )
        .deferred();
        assert!(deferred.is_hidden());
        assert_eq!(deferred.tools()[0].name, "deferred-demo:run");
        assert_eq!(deferred.dag_nodes()[0].id, "deferred-demo:run");

        let hidden_tool = hidden_tool_with_options("demo:legacy", "Legacy demo.", vec![]);
        assert!(hidden_tool.hidden);
    }

    #[test]
    fn explicit_policy_declaration_preserves_descriptor_identity() {
        let descriptor = hidden_tool_with_options(
            "semgrep:scan",
            "Scan with Semgrep.",
            vec![opt("target", OptionType::Path, "Path.")],
        );
        let before = descriptor.clone();
        let policy = ToolPolicy::new(
            ToolPhase::Scan,
            RuntimeRequirement::Never,
            ToolEffect::Read,
            WorkspaceRequirement::Required,
            FindingStoreRequirement::Required,
        );
        let module = builtin_module(
            "semgrep",
            "Semgrep",
            ModuleKind::Scan,
            "Static analysis",
            tools_with_policy(policy, vec![descriptor]),
            vec![],
        );
        let after = &module.tools()[0];

        assert_eq!(before.phase, ToolPhase::Operate);
        assert_eq!(after.phase, ToolPhase::Scan);
        assert_eq!(after.name, before.name);
        assert_eq!(after.headless, before.headless);
        assert_eq!(after.hidden, before.hidden);
        assert_eq!(after.runtime_requirement, before.runtime_requirement);
        assert_eq!(after.options, before.options);
        assert_eq!(after.effect, ToolEffect::Read);
        assert_eq!(after.approval, ApprovalPolicy::None);
        assert_eq!(after.workspace_requirement, WorkspaceRequirement::Required);
        assert_eq!(
            after.finding_store_requirement,
            FindingStoreRequirement::Required
        );
    }

    #[test]
    fn editable_prompt_metadata_is_serialized_and_path_backed() {
        let descriptor = tool("demo:scan", "Run demo.").with_prompt(editable_prompt(
            "scan instructions",
            "demo",
            "scan",
            "DEMO_PROMPT",
            "Review the target.".to_string(),
        ));

        let value = serde_json::to_value(&descriptor).unwrap();

        assert_eq!(value["prompts"][0]["role"], "scan instructions");
        assert_eq!(value["prompts"][0]["optionKey"], "DEMO_PROMPT");
        assert_eq!(
            descriptor.prompts[0].override_relative_path(),
            std::path::PathBuf::from(".kuzushi/prompts/demo/scan.md")
        );
    }

    #[test]
    fn editable_prompt_requires_a_declared_canonical_option() {
        let tool = tool("demo:scan", "Run demo.")
            .with_prompt(editable_prompt(
                "scan instructions",
                "demo",
                "scan",
                "DEMO_PROMPT",
                "Review the target.".to_string(),
            ))
            .with_policy(workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Optional,
            ));
        let module = builtin_module(
            "demo",
            "Demo",
            ModuleKind::Defense,
            "Demo module",
            vec![tool],
            vec![],
        );

        let error = module.validate_declared_policy().unwrap_err().to_string();

        assert!(error.contains("undeclared option"));
        assert!(error.contains("DEMO_PROMPT"));
    }

    #[test]
    fn builtin_policy_must_be_declared_before_registration() {
        let module = builtin_module(
            "unsafe-default",
            "Unsafe Default",
            ModuleKind::Defense,
            "Missing policy regression fixture.",
            vec![tool("unsafe-default:run", "Run without policy.")],
            vec![],
        );

        let error = module.validate_declared_policy().unwrap_err().to_string();

        assert!(error.contains("has no descriptor-owned policy"), "{error}");
    }

    #[test]
    fn option_builders_set_contract_flags_without_exposing_mutation() {
        let option = opt("mode", OptionType::Enum, "Mode.")
            .required()
            .advanced()
            .evasion()
            .default(json!("auto"))
            .choices(&["auto", "manual"]);

        assert_eq!(option.name, "mode");
        assert!(option.required);
        assert!(option.advanced);
        assert!(option.evasion);
        assert_eq!(option.default, Some(json!("auto")));
        assert_eq!(option.choices, vec!["auto", "manual"]);
    }

    #[test]
    fn common_option_helpers_keep_expected_names_and_types() {
        assert_eq!(target_option().option_type, OptionType::Path);
        assert_eq!(model_option().name, "model");
        assert!(model_option().advanced);
        assert_eq!(max_findings_option(7).default, Some(json!(7)));
        assert!(fingerprint_option().required);
        assert_eq!(binary_option("Binary path.").option_type, OptionType::Path);
        assert_eq!(mcps_option().default, Some(json!(true)));
        assert!(mcps_option().advanced);
        assert_eq!(
            allow_deterministic_fallback_option().default,
            Some(json!(false))
        );
        assert_eq!(joern_cpg_option().option_type, OptionType::Path);
        assert_eq!(mcp_tool_timeout_ms_option().default, Some(json!(60000)));
    }
}
