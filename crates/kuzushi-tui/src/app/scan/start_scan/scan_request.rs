use super::*;
use kuzushi_core::{OptionScope, OptionTarget, ToolOptionStore};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const SCAN_TOOL_NAME: &str = "sast:scan";

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EffectiveScanOption {
    name: String,
    value: Value,
    scope: OptionScope,
}

impl EffectiveScanOption {
    fn new(name: &str, value: &Value, scope: OptionScope) -> Self {
        Self {
            name: name.to_string(),
            value: value.clone(),
            scope,
        }
    }
}

pub(crate) struct ScanStartRequest {
    pub(super) run_id: String,
    pub(super) target_root: PathBuf,
    pub(super) db_path: PathBuf,
    pub(super) input: serde_json::Value,
    pub(super) effective_options: Vec<EffectiveScanOption>,
    pub(super) registry: ModuleRegistry,
    pub(super) config: V2Config,
    pub(super) thinking_level: Option<String>,
}

pub(crate) fn scan_input_with_run_id(
    mut input: serde_json::Value,
    run_id: &str,
) -> serde_json::Value {
    if let serde_json::Value::Object(object) = &mut input {
        object.insert("runId".to_string(), serde_json::json!(run_id));
    }
    input
}

pub(crate) fn effective_scan_options(
    registry: &ModuleRegistry,
    store: &ToolOptionStore,
) -> Vec<EffectiveScanOption> {
    let mut options = BTreeMap::new();
    for scope in [
        OptionScope::Global,
        OptionScope::Workspace,
        OptionScope::Session,
    ] {
        merge_scan_options(registry, store, scope, &OptionTarget::All, &mut options);
        merge_scan_options(
            registry,
            store,
            scope,
            &OptionTarget::Module("sast".to_string()),
            &mut options,
        );
        merge_scan_options(
            registry,
            store,
            scope,
            &OptionTarget::Tool(SCAN_TOOL_NAME.to_string()),
            &mut options,
        );
    }
    options.into_values().collect()
}

fn merge_scan_options(
    registry: &ModuleRegistry,
    store: &ToolOptionStore,
    scope: OptionScope,
    target: &OptionTarget,
    options: &mut BTreeMap<String, EffectiveScanOption>,
) {
    let Some(values) = store.values_for(scope, target) else {
        return;
    };
    for (name, value) in values {
        if scan_descriptor_accepts_option(registry, name) {
            options.insert(name.clone(), EffectiveScanOption::new(name, value, scope));
        }
    }
}

fn scan_descriptor_accepts_option(registry: &ModuleRegistry, name: &str) -> bool {
    registry.resolve_tool(SCAN_TOOL_NAME).is_some_and(|tool| {
        tool.options
            .iter()
            .any(|spec| spec.matches_name_or_alias(name))
    })
}

pub(crate) fn scan_options_log_message(options: &[EffectiveScanOption]) -> String {
    if options.is_empty() {
        return "0 stored options in effect — type `options sast:scan` or `tasks` before scanning"
            .to_string();
    }
    format!(
        "{} stored {} in effect — {}",
        options.len(),
        option_count_label(options.len()),
        scan_option_preview(options)
    )
}

fn option_count_label(count: usize) -> &'static str {
    if count == 1 {
        "option"
    } else {
        "options"
    }
}

fn scan_option_preview(options: &[EffectiveScanOption]) -> String {
    let mut parts = options
        .iter()
        .take(4)
        .map(format_effective_scan_option)
        .collect::<Vec<_>>();
    if options.len() > parts.len() {
        parts.push(format!("+{} more", options.len() - parts.len()));
    }
    parts.join(", ")
}

fn format_effective_scan_option(option: &EffectiveScanOption) -> String {
    format!(
        "{}={} ({})",
        option.name,
        option_value_label(&option.value),
        scope_label(option.scope)
    )
}

fn option_value_label(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn scope_label(scope: OptionScope) -> &'static str {
    match scope {
        OptionScope::Global => "global",
        OptionScope::Workspace => "workspace",
        OptionScope::Session => "session",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_input_with_run_id_adds_internal_artifact_identity() {
        let input = scan_input_with_run_id(serde_json::json!({"triage": false}), "scan-tui");

        assert_eq!(input["runId"], serde_json::json!("scan-tui"));
        assert_eq!(input["triage"], serde_json::json!(false));
    }

    #[test]
    fn effective_scan_options_log_uses_descriptor_filter_and_precedence() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "ui.auto_open_activity",
            serde_json::json!(false),
        );
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "triage",
            serde_json::json!(true),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool(SCAN_TOOL_NAME.to_string()),
            "maxFindings",
            serde_json::json!(12),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool(SCAN_TOOL_NAME.to_string()),
            "triage",
            serde_json::json!(false),
        );

        let options = effective_scan_options(&registry, &store);
        let message = scan_options_log_message(&options);

        assert_eq!(options.len(), 2);
        assert!(message.contains("2 stored options in effect"), "{message}");
        assert!(message.contains("maxFindings=12 (workspace)"), "{message}");
        assert!(message.contains("triage=false (session)"), "{message}");
        assert!(!message.contains("ui.auto_open_activity"), "{message}");
    }

    #[test]
    fn empty_scan_options_log_points_to_sast_options() {
        let message = scan_options_log_message(&[]);

        assert!(message.contains("0 stored options in effect"), "{message}");
        assert!(message.contains("options sast:scan"), "{message}");
        assert!(message.contains("before scanning"), "{message}");
    }
}
