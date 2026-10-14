use super::{PlanningOptionOverrides, PlanningTaskId};
use anyhow::Result;
use kuzushi_core::modules::OptionSpec;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) fn planning_task_explicit_input(
    task: PlanningTaskId,
    overrides: &PlanningOptionOverrides,
) -> Value {
    let mut input = planning_task_preset_input(task);
    merge_planning_override(&mut input, overrides.get(&task));
    input
}

pub(crate) fn planning_task_preset_input(task: PlanningTaskId) -> Value {
    match task {
        PlanningTaskId::ImportThreatModel => json!({"activate": false}),
        // Legacy decode-only rows keep their historical presets so older
        // saved plans replay unchanged. The merged BuildThreatModel row has
        // no preset: methodology and seedMode arrive through the
        // descriptor-driven options editor.
        PlanningTaskId::BuildPastaThreatModel => json!({
            "methodology": "pasta",
            "outputDir": ".kuzushi/threat-model-pasta",
        }),
        PlanningTaskId::BuildStrideThreatModel => json!({
            "methodology": "stride",
        }),
        // The planner's decomposition row closes the loop: the shard
        // candidates also materialize as the nested project-scope tree.
        PlanningTaskId::DecomposeModules => json!({
            "emitScopes": true,
        }),
        _ => json!({}),
    }
}

fn merge_planning_override(input: &mut Value, override_values: Option<&BTreeMap<String, Value>>) {
    let Some(override_values) = override_values else {
        return;
    };
    let Some(object) = input.as_object_mut() else {
        return;
    };
    object.extend(
        override_values
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
}

pub(super) fn option_storage_names(spec: &OptionSpec) -> Vec<&str> {
    std::iter::once(spec.name.as_str())
        .chain(spec.aliases.iter().map(String::as_str))
        .chain(spec.deprecated_aliases.iter().map(String::as_str))
        .collect()
}

pub(super) fn next_enum_value(spec: &OptionSpec, current: Option<&str>) -> Result<String> {
    if spec.choices.is_empty() {
        anyhow::bail!("{} has no enum choices", spec.name);
    }
    let next_index = current
        .and_then(|value| spec.choices.iter().position(|choice| choice == value))
        .map(|index| (index + 1) % spec.choices.len())
        .unwrap_or(0);
    Ok(spec.choices[next_index].clone())
}
