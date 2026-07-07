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
    fn phase_stamping_is_display_metadata_only() {
        // Stamping must set `phase` and leave every dispatch-relevant field
        // (name, headless, hidden, runtime_requirement, options) untouched —
        // proving phase is display grouping, not execution input.
        let module = builtin_module(
            "semgrep",
            "Semgrep",
            ModuleKind::Scan,
            "Static analysis",
            vec![hidden_tool_with_options(
                "semgrep:scan",
                "Scan with Semgrep.",
                vec![opt("target", OptionType::Path, "Path.")],
            )],
            vec![],
        );
        let before = module.tools()[0].clone();
        let stamped = module.with_stamped_phases();
        let after = &stamped.tools()[0];

        assert_eq!(before.phase, ToolPhase::Operate); // default before stamping
        assert_eq!(after.phase, ToolPhase::Hunt); // canonical semgrep phase
        assert_eq!(after.name, before.name);
        assert_eq!(after.headless, before.headless);
        assert_eq!(after.hidden, before.hidden);
        assert_eq!(after.runtime_requirement, before.runtime_requirement);
        assert_eq!(after.options, before.options);
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
