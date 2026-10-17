use super::*;

pub(super) fn tool() -> ToolDescriptor {
    hidden_tool_with_options("systems-hunt:deep-semantic-cwe-select",
        "Propose CWE classes from bounded repository-wide source prefixes. Auxiliary Labs planning; no tools, findings, discovery jobs or phase completion. Selected discovery scopes are unsupported. Review proposals before separate work.", options())
        .with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Always,
            FindingStoreRequirement::Optional))
        .with_allowance_category(AllowanceCategory::Scope)
        .with_discovery_maturity(ModuleMaturity::Labs)
        .without_phase_result()
        .with_prompt(systems_prompt("deep semantic CWE selection", "deep-semantic-cwe-select",
            "SYSTEMS_DEEP_CWE_PROMPT", crate::capabilities::systems_hunt::deep_semantic_cwe_system_prompt()))
}

fn options() -> Vec<OptionSpec> {
    let mut options = systems_hunt_options();
    for option in &mut options {
        configure(option);
    }
    options.extend([
        bound_threat_model_option(),
        int_option("maxSourceBytes", "Maximum source-prefix bytes across inspected files. Inventory shares its own 512 MiB inspection ceiling.",
            160 * 1024, &["max_source_bytes"]).integer_range(1, 16 * 1024 * 1024),
    ]);
    options
}

fn configure(option: &mut OptionSpec) {
    match option.name.as_str() {
        "maxFiles" => configure_limit(option, 80, 100_000),
        "headBytes" => configure_limit(option, 2048, 256 * 1024),
        "maxCweClasses" => configure_limit(option, 6, 32),
        _ => configure_other(option),
    }
}

fn configure_limit(option: &mut OptionSpec, default: i64, maximum: i64) {
    option.default = Some(json!(default));
    option.minimum = Some(1);
    option.maximum = Some(maximum);
    option.advanced = false;
}

fn configure_other(option: &mut OptionSpec) {
    if option.name == "thinkingLevel" {
        option.description =
            "Reasoning override. Omit to retain the selected runtime setting.".into();
    }
    if crate::capabilities::systems_hunt::cwe_proposal_option_supported(&option.name) {
        option.advanced = false;
        return;
    }
    option.default = None;
    option.advanced = true;
    option.description = "Compatibility only; unsupported by standalone CWE proposals. Remove this option. No scan, trigger, finding or artifact-directory setting is consumed.".into();
}
