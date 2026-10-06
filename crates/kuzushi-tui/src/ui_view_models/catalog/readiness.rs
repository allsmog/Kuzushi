use super::{CapabilityActionSpec, ShellApp};
use serde_json::json;

/// These are preparation hints, never permission or an execution guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogReadiness {
    pub(crate) label: &'static str,
    pub(crate) next: String,
}

pub(super) fn unassessed() -> CatalogReadiness {
    hint("UNASSESSED", "Select this action to review inputs")
}

pub(super) fn action_readiness(app: &ShellApp, spec: CapabilityActionSpec) -> CatalogReadiness {
    if app.target().is_none() {
        return hint("TARGET REQUIRED", "Enter selects a target");
    }
    let Some(tool) = spec.required_tool else {
        return navigation_hint(spec.command);
    };
    let input = match app
        .registry()
        .prepare_tool_input(tool, json!({}), Some(app.option_store()))
    {
        Ok(input) => input,
        Err(_) => return hint("INPUT REQUIRED", &format!("options {tool}")),
    };
    if !app
        .registry()
        .tool_wants_runtime(tool, &input, app.config())
    {
        return hint("REVIEW INPUTS", &format!("options {tool}"));
    }
    model_hint(app, tool, &input)
}

fn model_hint(app: &ShellApp, tool: &str, input: &serde_json::Value) -> CatalogReadiness {
    let inline_model = input.get("model").and_then(serde_json::Value::as_str);
    let model = inline_model.or(app.config().model.as_deref());
    if model.is_none_or(|value| value.trim().is_empty()) {
        return hint("MODEL REQUIRED", "model selects a model");
    }
    if kuzushi_core::runtime::resolve_explicit_model(
        tool,
        inline_model.map(str::to_string),
        app.config().model.as_deref(),
    )
    .is_err()
    {
        return hint("MODEL CONFIG", "model selects a valid model");
    }
    hint("REVIEW INPUTS", &format!("options {tool}"))
}

fn navigation_hint(command: &str) -> CatalogReadiness {
    match command {
        "next" | "scan" => hint("REVIEW PLAN", "Enter loads the planner command"),
        "findings" => hint("OPEN REVIEW", "Enter loads the review command"),
        _ => hint("REVIEW INPUTS", "Enter loads an editable command"),
    }
}

fn hint(label: &'static str, next: &str) -> CatalogReadiness {
    CatalogReadiness {
        label,
        next: next.to_string(),
    }
}
