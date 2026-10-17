use super::*;

pub(super) fn tool() -> ToolDescriptor {
    hidden_tool_with_options("systems-hunt:systems-context-gatherer",
        "Inspect bounded systems-source prefixes and rank lexical surfaces. Auxiliary context only; no code index, model calls, source execution or phase completion.", options())
        .with_policy(tool_policy(ToolPhase::Map, RuntimeRequirement::Never, ToolEffect::Read,
            WorkspaceRequirement::Required, FindingStoreRequirement::Optional))
        .without_phase_result()
}

fn options() -> Vec<OptionSpec> {
    let mut options = systems_hunt_options();
    for option in &mut options {
        configure_option(option);
    }
    options.push(int_option("maxSourceBytes", "Maximum source-prefix bytes across inspected files. Shares the repository inventory's 512 MiB combined inspection ceiling.",
        16 * 1024 * 1024, &["max_source_bytes"]).integer_range(1, 512 * 1024 * 1024));
    options
        .last_mut()
        .expect("aggregate source option was added")
        .advanced = false;
    options
}

fn configure_option(option: &mut OptionSpec) {
    let maximum = match option.name.as_str() {
        "target" | "includeNonProduction" => {
            option.advanced = false;
            return;
        }
        "maxFiles" => 100_000,
        "headBytes" => 256 * 1024,
        "maxSurfaces" => 1000,
        _ => {
            compatibility_only(option);
            return;
        }
    };
    option.minimum = Some(1);
    option.maximum = Some(maximum);
    option.advanced = false;
}

fn compatibility_only(option: &mut OptionSpec) {
    option.default = None;
    option.advanced = true;
    option.description = "Compatibility only; unsupported by standalone systems context. Remove this option. No model, prompt, artifact directory or pipeline handoff is consumed.".into();
}
