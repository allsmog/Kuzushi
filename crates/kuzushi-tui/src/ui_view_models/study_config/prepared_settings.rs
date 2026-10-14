//! Readable, exhaustive projection of frozen values using current descriptor help.
use crate::ui_view_models::options::option_display_name;
use kuzushi_core::modules::OptionSpec;
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SettingGroup {
    Scan,
    Advanced,
    LegacyExecution,
    Bindings,
}

impl SettingGroup {
    fn from_field(key: &str, spec: Option<&OptionSpec>) -> Self {
        if legacy_execution_field(key) {
            return Self::LegacyExecution;
        }
        match spec {
            Some(spec) if spec.advanced => Self::Advanced,
            Some(_) => Self::Scan,
            None => Self::Bindings,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Scan => "SCAN SETTINGS",
            Self::Advanced => "ADVANCED SETTINGS",
            Self::LegacyExecution => "LEGACY EXECUTION FIELDS",
            Self::Bindings => "RECORDED BINDINGS",
        }
    }

    fn heading(self) -> Vec<String> {
        let mut lines = vec![String::new(), self.label().into()];
        if self == Self::LegacyExecution {
            lines.push("Retained for inspection. This workflow offers no target execution, reproducer or patch actions. Values remain exactly as recorded.".into());
        }
        lines
    }
}

pub(super) fn settings_lines(input: &Value, specs: &[OptionSpec]) -> Vec<String> {
    let Some(fields) = input.as_object() else {
        return vec!["Recorded input is not an object. JSON retains its exact value.".into()];
    };
    let mut rows = fields
        .iter()
        .map(|(key, value)| {
            let spec = specs.iter().find(|spec| spec.name == *key);
            (SettingGroup::from_field(key, spec), key, value, spec)
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|(group, key, _, _)| (*group, *key));
    let mut lines = vec![format!(
        "{} recorded fields. Empty text and null remain distinct.",
        rows.len()
    )];
    let mut previous_group = None;
    for (group, key, value, spec) in rows {
        if previous_group != Some(group) {
            lines.extend(group.heading());
            previous_group = Some(group);
        }
        lines.extend(setting_card(group, key, value, spec));
    }
    lines
}

fn setting_card(
    group: SettingGroup,
    key: &str,
    value: &Value,
    spec: Option<&OptionSpec>,
) -> Vec<String> {
    let key = display_key(key);
    let mut lines = vec![
        format!("{} ({key})", option_display_name(&key)),
        format!("Value: {value}"),
    ];
    if let Some(spec) = spec.filter(|spec| setting_help_visible(group, spec)) {
        lines.push(spec.description.clone());
    }
    lines.push(String::new());
    lines
}

fn setting_help_visible(group: SettingGroup, spec: &OptionSpec) -> bool {
    group != SettingGroup::LegacyExecution && !spec.description.is_empty()
}

fn legacy_execution_field(key: &str) -> bool {
    // Presentation classification only. Dispatch and plan policy remain in Core.
    const FIELDS: &[&str] = &[
        "autoPatch",
        "auto_patch",
        "patch",
        "patching",
        "maxIterations",
        "max_iterations",
        "poc",
        "pocHarness",
        "poc_harness",
        "pocExecution",
        "poc_execution",
        "verify",
        "dynamicAnalysis",
        "dynamic_analysis",
        "cryptoBehavioralTesting",
        "crypto_behavioral_testing",
        "runtimeExploitabilityClaims",
        "runtime_exploitability_claims",
        "executionProofStates",
        "execution_proof_states",
    ];
    FIELDS.contains(&key)
}

fn display_key(key: &str) -> String {
    if key.chars().any(char::is_control) {
        return Value::String(key.into()).to_string();
    }
    key.into()
}

#[cfg(test)]
mod tests;
