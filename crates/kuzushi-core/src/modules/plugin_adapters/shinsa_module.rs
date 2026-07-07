use super::*;

pub(in crate::modules) fn shinsa_module() -> BuiltinModule {
    builtin_module(
        "shinsa",
        "Shinsa Compliance",
        ModuleKind::Governance,
        "Compliance assessment wrapper around the shinsa-plugin Claude Code plugin.",
        vec![
            tool_with_options(
                "shinsa:scan",
                "Run a full ISO 27001 Annex A compliance assessment.",
                shinsa_tool_options(),
            ),
            hidden_tool_with_options(
                "shinsa:quick-check",
                "Run a fast ISO 27001 Annex A check.",
                shinsa_tool_options(),
            ),
            tool_with_options(
                "shinsa:nist-scan",
                "Run a full NIST SP 800-53 Rev 5 compliance assessment.",
                shinsa_tool_options(),
            ),
            hidden_tool_with_options(
                "shinsa:nist-quick-check",
                "Run a fast NIST SP 800-53 Rev 5 check.",
                shinsa_tool_options(),
            ),
            tool("shinsa:frameworks", "List supported compliance frameworks."),
        ],
        vec![
            dag("shinsa:scan", "assessment", &["context:build"]),
            dag("shinsa:nist-scan", "assessment", &["context:build"]),
        ],
    )
}

fn shinsa_tool_options() -> Vec<OptionSpec> {
    let mut options = vec![target_option(), plugin_root_option()];
    options.extend([
        opt(
            "outputDir",
            OptionType::Path,
            "Directory for shinsa assessment artifacts.",
        )
        .aliases(&["output_dir"])
        .default(json!("shinsa-output"))
        .advanced(),
        opt(
            "controls",
            OptionType::StringList,
            "Compliance controls to include.",
        )
        .advanced(),
        opt("family", OptionType::String, "Control family filter.").advanced(),
        opt("depth", OptionType::Enum, "Assessment depth.")
            .choices(&["full", "quick"])
            .default(json!("full")),
        opt(
            "severity",
            OptionType::StringList,
            "Severity filter for generated findings.",
        )
        .advanced(),
    ]);
    options.push(model_option());
    options
}

pub(in crate::modules) fn run_vuln_scout_audit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    run_plugin_finding_adapter(
        PluginAdapterSpec {
            tool_name: "vuln-scout:audit",
            tool_slug: "vuln-scout",
            package_name: "@kuzushi/vuln-scout",
            env_var: "KUZUSHI_VULN_SCOUT_PLUGIN",
            install_hint: "pnpm add @kuzushi/vuln-scout",
            prompt_title:
                "Run a whitebox pentest audit using Vuln Scout-style read-only repository analysis.",
            allow_skill_filter: false,
        },
        input,
        ctx,
        runtime,
    )
}

pub(in crate::modules) fn run_tob_audit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    validate_requested_tob_skills(&input)?;
    run_plugin_finding_adapter(
        PluginAdapterSpec {
            tool_name: "tob:audit",
            tool_slug: "tob-audit",
            package_name: "@kuzushi/tob-skills",
            env_var: "KUZUSHI_TOB_SKILLS_DIR",
            install_hint: "pnpm add @kuzushi/tob-skills",
            prompt_title:
                "Run a Trail of Bits skills-style audit using read-only repository analysis.",
            allow_skill_filter: true,
        },
        input,
        ctx,
        runtime,
    )
}
