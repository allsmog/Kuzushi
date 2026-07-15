use super::{format_option_value, GuidedOptionChoice, GuidedOptionValue};
use kuzushi_core::modules::{OptionSpec, OptionType};
use serde_json::Value;

pub(super) fn option_choices(spec: &OptionSpec, current: Option<Value>) -> Vec<GuidedOptionChoice> {
    let mut choices = keep_current_choice(current.as_ref())
        .into_iter()
        .collect::<Vec<_>>();
    if current.is_none() && !spec.required {
        choices.push(automatic_default_choice());
    }
    append_typed_choices(&mut choices, spec, current.as_ref());
    choices.truncate(3);
    choices.push(other_choice(current.is_none() && choices.is_empty()));
    choices
}

fn automatic_default_choice() -> GuidedOptionChoice {
    GuidedOptionChoice {
        label: "Use automatic default".to_string(),
        description: "Leave this optional setting unset and use the tool's normal behavior."
            .to_string(),
        value: GuidedOptionValue::Keep,
        recommended: true,
    }
}

fn keep_current_choice(current: Option<&Value>) -> Option<GuidedOptionChoice> {
    let value = current?;
    Some(GuidedOptionChoice {
        label: format!("Keep {}", format_option_value(value)),
        description: "Use the prepared value from defaults, stored options, and presets."
            .to_string(),
        value: GuidedOptionValue::Keep,
        recommended: true,
    })
}

fn append_typed_choices(
    choices: &mut Vec<GuidedOptionChoice>,
    spec: &OptionSpec,
    current: Option<&Value>,
) {
    match spec.option_type {
        OptionType::Bool => push_bool_choices(choices, current),
        OptionType::Enum => push_enum_choices(choices, spec, current),
        _ => {}
    }
}

fn other_choice(recommended: bool) -> GuidedOptionChoice {
    GuidedOptionChoice {
        label: "Other…".to_string(),
        description: "Enter another value; descriptor validation runs before it is accepted."
            .to_string(),
        value: GuidedOptionValue::Other,
        recommended,
    }
}

fn push_bool_choices(choices: &mut Vec<GuidedOptionChoice>, current: Option<&Value>) {
    let current = current.and_then(Value::as_bool);
    for value in [true, false] {
        if current != Some(value) {
            choices.push(bool_choice(value, current.is_none() && value));
        }
    }
}

fn bool_choice(value: bool, recommended: bool) -> GuidedOptionChoice {
    GuidedOptionChoice {
        label: if value { "Set yes" } else { "Set no" }.to_string(),
        description: format!("Set this option to {value}."),
        value: GuidedOptionValue::Set(Value::Bool(value)),
        recommended,
    }
}

fn push_enum_choices(
    choices: &mut Vec<GuidedOptionChoice>,
    spec: &OptionSpec,
    current: Option<&Value>,
) {
    let current = current.and_then(Value::as_str);
    for value in spec
        .choices
        .iter()
        .filter(|value| Some(value.as_str()) != current)
    {
        choices.push(enum_choice(
            spec,
            value,
            current.is_none() && choices.is_empty(),
        ));
    }
}

fn enum_choice(spec: &OptionSpec, value: &str, recommended: bool) -> GuidedOptionChoice {
    GuidedOptionChoice {
        label: format!("Use {value}"),
        description: format!("Set {} to {value}.", spec.name),
        value: GuidedOptionValue::Set(Value::String(value.to_string())),
        recommended,
    }
}
