use crate::modules::{OptionSpec, ToolDescriptor, ValidatedToolOptions};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

pub(in crate::modules) fn prepare_strategy_options(
    tool: &ToolDescriptor,
    options: ValidatedToolOptions,
) -> Result<Value> {
    let ValidatedToolOptions {
        mut value,
        supplied,
    } = options;
    if tool.name != "agentic-sast:scan" {
        return Ok(value);
    }
    if !chunked_requested(&value) {
        reject_chunk_controls(&value)?;
        return Ok(value);
    }
    validate_chunked_shared_options(&value)?;
    remove_standard_defaults(tool, &mut value, &supplied)?;
    Ok(value)
}

fn chunked_requested(value: &Value) -> bool {
    value
        .get("strategy")
        .and_then(Value::as_str)
        .is_some_and(|strategy| strategy.trim().eq_ignore_ascii_case("chunked"))
}

pub(in crate::modules) fn strategy_supports_option(name: &str, input: &Value, field: &str) -> bool {
    if name != "agentic-sast:scan" || !chunked_requested(input) {
        return true;
    }
    chunked_option_names().contains(field) || field == "strategy"
}

fn validate_chunked_shared_options(input: &Value) -> Result<()> {
    reject_bound_context(input)?;
    anyhow::ensure!(
        input.get("passes").and_then(Value::as_u64) == Some(1),
        "chunked discovery supports one pass per job; plan repetitions as separate explicit jobs"
    );
    anyhow::ensure!(input.get("focus").and_then(Value::as_str).is_none_or(|focus| focus.trim().is_empty()), "agentic-sast:scan option focus is not supported with strategy=chunked; rerun with strategy=standard");
    Ok(())
}

fn chunked_option_names() -> BTreeSet<String> {
    crate::modules::agentic_sast_chunk_only_options()
        .into_iter()
        .map(|option| option.name)
        .chain(
            ["target", "model", "allowanceRef", "passes"]
                .into_iter()
                .map(String::from),
        )
        .collect()
}

pub(in crate::modules) fn describe_strategy_options(options: &mut [OptionSpec]) {
    let supported = chunked_option_names();
    for option in options
        .iter_mut()
        .filter(|option| !supported.contains(&option.name) && option.name != "strategy")
    {
        option.description = format!("Standard strategy only. {}", option.description);
    }
}

fn remove_standard_defaults(
    tool: &ToolDescriptor,
    input: &mut Value,
    supplied: &BTreeSet<String>,
) -> Result<()> {
    let supported = chunked_option_names();
    let object = input
        .as_object_mut()
        .context("strategy preparation requires canonical object input")?;
    for option in tool
        .options
        .iter()
        .filter(|option| !supported.contains(&option.name) && option.name != "strategy")
    {
        let field = &option.name;
        anyhow::ensure!(!supplied.contains(field) || inert_context_option(field, object.get(field)), "agentic-sast:scan option {field} requires strategy=standard. Chunked analysis cannot honor this setting. Remove it or review a separate standard job. No model request started.");
        object.remove(field);
    }
    Ok(())
}

const CONTEXT_OPTIONS: [&str; 4] = [
    "scanScopeRef",
    "scanContextRef",
    "threatModelRef",
    "threatModelDigestRef",
];

fn inert_context_option(field: &str, value: Option<&Value>) -> bool {
    if CONTEXT_OPTIONS.contains(&field) {
        return value.is_some_and(Value::is_null);
    }
    field == "focus"
        && value
            .and_then(Value::as_str)
            .is_some_and(|text| text.trim().is_empty())
}

fn reject_chunk_controls(input: &Value) -> Result<()> {
    for option in crate::modules::agentic_sast_chunk_only_options() {
        let field = option.name;
        anyhow::ensure!(input.get(&field).is_none(), "agentic-sast:scan option {field} requires strategy=chunked. Remove this setting for standard discovery, or review a separate chunked job. No model request started.");
    }
    Ok(())
}

fn reject_bound_context(input: &Value) -> Result<()> {
    for field in CONTEXT_OPTIONS {
        anyhow::ensure!(input.get(field).is_none_or(Value::is_null), "strategy=chunked cannot honor {field}; use strategy=standard for accepted scope and context. No model request started.");
    }
    Ok(())
}
