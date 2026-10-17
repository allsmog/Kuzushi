use super::*;

pub(super) fn tool() -> ToolDescriptor {
    hidden_tool_with_options("systems-hunt:systems-invariant-extract",
        "Draft safety assumptions from explicitly supplied systems context and bounded source prefixes. Auxiliary Labs Context work; review drafts before accepting context. No tools, findings, automatic repair or phase completion. Selected discovery scopes are unsupported.", options())
        .with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Always,
            FindingStoreRequirement::Optional))
        .with_allowance_category(AllowanceCategory::Context)
        .with_discovery_maturity(ModuleMaturity::Labs)
        .without_phase_result()
        .with_prompt(systems_prompt("invariant context drafts", "invariants",
            "SYSTEMS_INVARIANT_PROMPT", crate::capabilities::systems_hunt::invariant_draft_system_prompt()))
}

fn options() -> Vec<OptionSpec> {
    let mut options = systems_hunt_options();
    for option in &mut options {
        configure(option);
    }
    options.extend([
        bound_threat_model_option(),
        int_option("maxSourceBytes", "Maximum source-prefix bytes across inspected files. Inventory has a separate 512 MiB combined inspection ceiling.",
            160 * 1024, &["max_source_bytes"]).integer_range(1, 16 * 1024 * 1024),
        int_option("maxInvariants", "Maximum draft safety assumptions returned by one request.",
            8, &["max_invariants"]).integer_range(1, 64),
    ]);
    options
}

fn configure(option: &mut OptionSpec) {
    match option.name.as_str() {
        "maxFiles" => configure_limit(option, 80, 100_000),
        "headBytes" => configure_limit(option, 2048, 256 * 1024),
        "maxSurfaces" => configure_limit(option, 24, 1000),
        "context" => {
            option.required = true;
            option.advanced = false;
            option.description = "Explicit data from systems-hunt:systems-context-gatherer, at most 4 MiB. Only selected surface ids, paths and lines reach the model alongside separately captured current source prefixes. Lexical annotations, packs and caller coverage metadata are omitted. No implicit gathering.".into();
        }
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
    if crate::capabilities::systems_hunt::invariant_draft_option_supported(&option.name) {
        option.advanced = false;
        return;
    }
    option.default = None;
    option.advanced = true;
    option.description = "Compatibility only; unsupported by standalone invariant drafts. Remove this option. No triggers, findings, pipeline handoffs or artifact directory are consumed.".into();
}
