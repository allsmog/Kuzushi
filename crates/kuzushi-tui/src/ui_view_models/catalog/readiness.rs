use super::{CapabilityActionSpec, ShellApp};
use serde_json::json;

/// These are preparation hints, never permission or an execution guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogReadiness {
    pub(crate) label: &'static str,
    pub(crate) next: String,
    pub(crate) executables: Vec<kuzushi_core::modules::ExecutableRequirement>,
}

pub(super) fn unassessed() -> CatalogReadiness {
    hint("UNASSESSED", "Select this action to review inputs")
}

pub(super) fn action_readiness(app: &ShellApp, spec: CapabilityActionSpec) -> CatalogReadiness {
    if app.target().is_none() {
        return hint("TARGET REQUIRED", "target <path> selects a repository");
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
    let executables = app.registry().executable_requirements(tool, &input);
    let mut readiness = prepared_readiness(app, tool, &input, &executables);
    readiness.executables = executables;
    readiness
}

fn prepared_readiness(
    app: &ShellApp,
    tool: &str,
    input: &serde_json::Value,
    executables: &[kuzushi_core::modules::ExecutableRequirement],
) -> CatalogReadiness {
    if let Some(readiness) = executable_hint(app, tool, executables) {
        return readiness;
    }
    if !app.registry().tool_wants_runtime(tool, input, app.config()) {
        return hint("REVIEW INPUTS", &format!("options {tool}"));
    }
    model_hint(app, tool, input)
}

fn executable_hint(
    app: &ShellApp,
    tool: &str,
    executables: &[kuzushi_core::modules::ExecutableRequirement],
) -> Option<CatalogReadiness> {
    if executables.is_empty() {
        return None;
    }
    let target = app.target()?;
    let cache = app.workbench_cache().borrow();
    let key = cache.executable_options_key(executables.to_vec());
    match cache.cached_executable_options(target, &key) {
        crate::app::ViewDataState::Ready(missing) if missing.is_empty() => None,
        crate::app::ViewDataState::Ready(missing) => Some(hint(
            "DEPENDENCY MISSING",
            &format!("options {tool} · set {} · r recheck", missing.join(", ")),
        )),
        _ => Some(hint(
            "CHECKING DEPENDENCIES",
            "Presence check only; no command runs",
        )),
    }
}

fn model_hint(app: &ShellApp, tool: &str, input: &serde_json::Value) -> CatalogReadiness {
    let inline_model = input.get("model").and_then(serde_json::Value::as_str);
    let model = inline_model.or(app.config().model.as_deref());
    if model.is_none_or(|value| value.trim().is_empty()) {
        return hint("MODEL REQUIRED", "model selects a model");
    }
    let Ok(model) = kuzushi_core::runtime::resolve_explicit_model(
        tool,
        inline_model.map(str::to_string),
        app.config().model.as_deref(),
    ) else {
        return hint("MODEL CONFIG", "model selects a valid model");
    };
    if kuzushi_core::runtime::bind_model_auth(&model, &app.config().runtime.api_key_env).is_err() {
        return hint("RUNTIME CONFIG", "doctor checks model and runtime");
    }
    hint("REVIEW INPUTS", &format!("options {tool}"))
}

fn navigation_hint(command: &str) -> CatalogReadiness {
    match command {
        "next" | "scan" => hint("REVIEW PLAN", "Review the plan before starting work"),
        "findings" => hint("OPEN REVIEW", "findings opens the review queue"),
        _ => hint("REVIEW INPUTS", "Review inputs before submitting"),
    }
}

fn hint(label: &'static str, next: &str) -> CatalogReadiness {
    CatalogReadiness {
        label,
        next: next.to_string(),
        executables: Vec::new(),
    }
}
