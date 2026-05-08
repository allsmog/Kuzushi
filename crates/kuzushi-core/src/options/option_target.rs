use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "kebab-case")]
pub enum OptionTarget {
    All,
    Module(String),
    Tool(String),
}

pub(super) fn option_target_storage_key(target: &OptionTarget) -> String {
    option_module_target_id(target)
        .map(|module| format!("module/{module}"))
        .or_else(|| option_tool_target_id(target).map(|tool| format!("tool/{tool}")))
        .unwrap_or_else(|| "all".to_string())
}

pub(super) fn parse_option_binding_target<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
) -> Result<OptionTarget> {
    let target_kind = parts
        .next()
        .context("option binding key is missing target kind")?;
    parse_option_target(target_kind, parts.next())
}

fn option_module_target_id(target: &OptionTarget) -> Option<&str> {
    match target {
        OptionTarget::Module(module) => Some(module.as_str()),
        _ => None,
    }
}

fn option_tool_target_id(target: &OptionTarget) -> Option<&str> {
    match target {
        OptionTarget::Tool(tool) => Some(tool.as_str()),
        _ => None,
    }
}

fn parse_option_target(target_kind: &str, raw_target: Option<&str>) -> Result<OptionTarget> {
    parse_all_option_target(target_kind)
        .map(Ok)
        .unwrap_or_else(|| parse_named_option_target(target_kind, raw_target))
}

fn parse_all_option_target(target_kind: &str) -> Option<OptionTarget> {
    (target_kind == "all").then_some(OptionTarget::All)
}

fn parse_named_option_target(target_kind: &str, raw_target: Option<&str>) -> Result<OptionTarget> {
    let spec = option_target_spec(target_kind)
        .with_context(|| format!("unknown option target kind {target_kind:?}"))?;
    Ok((spec.build)(required_option_target(
        raw_target,
        spec.missing_message,
    )?))
}

struct OptionTargetSpec {
    kind: &'static str,
    missing_message: &'static str,
    build: fn(String) -> OptionTarget,
}

const OPTION_TARGET_SPECS: &[OptionTargetSpec] = &[
    OptionTargetSpec {
        kind: "module",
        missing_message: "module option binding key is missing module id",
        build: OptionTarget::Module,
    },
    OptionTargetSpec {
        kind: "tool",
        missing_message: "tool option binding key is missing tool id",
        build: OptionTarget::Tool,
    },
];

fn option_target_spec(target_kind: &str) -> Option<&'static OptionTargetSpec> {
    OPTION_TARGET_SPECS
        .iter()
        .find(|spec| spec.kind == target_kind)
}

fn required_option_target(raw_target: Option<&str>, message: &'static str) -> Result<String> {
    raw_target
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
        .context(message)
}
