use super::*;

pub(super) fn tool() -> ToolDescriptor {
    hidden_tool_with_options("systems-hunt:deep-semantic-hunt",
        "One source-only discovery request for explicitly selected CWE classes. Bounded source prefixes and exact accepted scope/context; no tools, implicit class selection, repair, source execution or follow-up jobs. Labs; findings remain unverified.", options())
        .with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Always,
            FindingStoreRequirement::Required))
        .with_allowance_category(AllowanceCategory::Discovery)
        .with_discovery_maturity(ModuleMaturity::Labs)
        .with_prompt(systems_prompt("deep semantic discovery", "deep-semantic-hunt",
            "SYSTEMS_DEEP_HUNT_PROMPT", crate::capabilities::systems_hunt::deep_semantic_hunt_system_prompt()))
}

fn options() -> Vec<OptionSpec> {
    let mut options = systems_hunt_options();
    for option in &mut options {
        configure(option);
    }
    options.extend([
        bound_threat_model_option(),
        opt("scanScopeRef", OptionType::Json,
            "Exact accepted discovery membership and inherited context-only files. Omitting this reference explicitly selects repository-wide prefix discovery.")
            .aliases(&["scan_scope_ref"]),
        opt("scanContextRef", OptionType::Json,
            "Exact authenticated frozen supporting context; null omits it. Reading this revision never changes active context.")
            .aliases(&["scan_context_ref"]),
        int_option("maxSourceBytes", "Maximum source-prefix bytes across inspected files; inventory retains its own 512 MiB inspection ceiling.",
            160 * 1024, &["max_source_bytes"]).integer_range(1,16 * 1024 * 1024),
    ]);
    options
        .last_mut()
        .expect("source byte limit was added")
        .advanced = false;
    let mut snapshot = int_option("maxSnapshotBytes",
        "Maximum full cited-source bytes retained for immutable observation binding after discovery. Exceeding it withholds candidates without another request; prefixes supplied to the model retain their separate source limit.",
        16 * 1024 * 1024, &["max_snapshot_bytes"]).integer_range(1,512 * 1024 * 1024);
    snapshot.advanced = false;
    options.push(snapshot);
    options
}

fn configure(option: &mut OptionSpec) {
    let limits = [
        ("maxFiles", 80, 100_000),
        ("headBytes", 2048, 256 * 1024),
        ("maxFindings", 10, 100),
        ("maxCweClasses", 6, 32),
    ];
    if let Some((_, default, maximum)) = limits.iter().find(|row| row.0 == option.name) {
        option.default = Some(json!(default));
        option.minimum = Some(1);
        option.maximum = Some(*maximum);
        option.advanced = false;
        return;
    }
    if crate::capabilities::systems_hunt::deep_discovery_option_supported(&option.name) {
        if option.name == "cwes" {
            option.required = true;
            option.description = "Explicit selected CWE ids or class objects. Required; no implicit class-selection request is performed.".into();
        }
        option.advanced = false;
        return;
    }
    option.default = None;
    option.advanced = true;
    option.description="Compatibility only; unsupported by source-only deep discovery. Remove this option. No implicit context gathering, trigger synthesis or proof work is performed.".into();
}
