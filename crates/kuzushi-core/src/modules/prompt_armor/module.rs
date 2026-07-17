use super::*;

const ACTIVE_POLICY: ToolPolicy = target_write_policy(
    ToolPhase::Scan,
    RuntimeRequirement::Always,
    FindingStoreRequirement::Required,
);
const REPORT_POLICY: ToolPolicy = target_write_policy(
    ToolPhase::Fix,
    RuntimeRequirement::Never,
    FindingStoreRequirement::Optional,
);
const CONFIG_POLICY: ToolPolicy = target_write_policy(
    ToolPhase::Scan,
    RuntimeRequirement::Never,
    FindingStoreRequirement::Optional,
);
const DIFF_POLICY: ToolPolicy = workspace_policy(
    ToolPhase::Scan,
    RuntimeRequirement::Never,
    FindingStoreRequirement::Optional,
);

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "prompt-armor",
        "PromptArmor",
        ModuleKind::Offense,
        "LLM red-team wrapper around promptarmor-plugin attack suites and mutations.",
        prompt_armor_tools(),
        vec![dag("prompt-armor:scan", "findings", &["context:build"])],
    )
}

fn prompt_armor_tools() -> Vec<ToolDescriptor> {
    vec![
        prompt_armor_scan_tool().with_policy(ACTIVE_POLICY),
        tool_with_options(
            "prompt-armor:analyze",
            "Statically analyze prompt-injection surface.",
            vec![target_option(), plugin_root_option(), model_option()],
        )
        .with_policy(ACTIVE_POLICY),
        prompt_armor_attack_tool().with_policy(ACTIVE_POLICY),
        prompt_armor_diff_tool().with_policy(DIFF_POLICY),
        prompt_armor_report_tool().with_policy(REPORT_POLICY),
        prompt_armor_config_tool().with_policy(CONFIG_POLICY),
    ]
}

fn prompt_armor_report_tool() -> ToolDescriptor {
    tool_with_options(
        "prompt-armor:report",
        "Generate a consolidated red-team report.",
        vec![
            target_option(),
            opt("output", OptionType::Path, "Report output path.")
                .target_write()
                .advanced(),
        ],
    )
}

fn prompt_armor_config_tool() -> ToolDescriptor {
    tool_with_options(
        "prompt-armor:config",
        "Inspect or scaffold promptarmor.yaml.",
        vec![
            target_option(),
            opt("action", OptionType::Enum, "Config action.")
                .choices(&["show", "init"])
                .default(json!("show")),
        ],
    )
}

fn prompt_armor_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "prompt-armor:scan",
        "Run a full LLM red-team scan.",
        prompt_armor_active_options(),
    )
}

fn prompt_armor_attack_tool() -> ToolDescriptor {
    tool_with_options(
        "prompt-armor:attack",
        "Send a single authorized attack payload and judge the response.",
        prompt_armor_active_options(),
    )
}

fn prompt_armor_active_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        plugin_root_option(),
        opt(
            "authorized",
            OptionType::Bool,
            "Confirm authorization to test.",
        )
        .default(json!(false)),
        opt(
            "payload",
            OptionType::String,
            "Single attack payload to test.",
        )
        .evasion(),
        model_option(),
    ]
}

fn prompt_armor_diff_tool() -> ToolDescriptor {
    tool_with_options(
        "prompt-armor:diff",
        "Diff two prior red-team runs.",
        vec![
            opt("runA", OptionType::Path, "Baseline prompt-armor run path.")
                .aliases(&["run_a"])
                .workspace_read()
                .required(),
            opt(
                "runB",
                OptionType::Path,
                "Comparison prompt-armor run path.",
            )
            .aliases(&["run_b"])
            .workspace_read()
            .required(),
        ],
    )
}

fn plugin_root_option() -> OptionSpec {
    opt(
        "pluginRoot",
        OptionType::Path,
        "Installed promptarmor-plugin root.",
    )
    .aliases(&["pluginPath", "plugin_root", "plugin_path"])
    .external_read()
    .advanced()
}
