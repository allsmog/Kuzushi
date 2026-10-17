use super::*;
use crate::workspace::inventory::SourcePrefixLimits;

pub(super) struct Limits {
    pub source: SourcePrefixLimits,
    pub max_classes: usize,
    pub include_non_production: bool,
}

pub(crate) fn cwe_proposal_option_supported(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "model"
            | "maxFiles"
            | "maxSourceBytes"
            | "headBytes"
            | "maxCweClasses"
            | "includeNonProduction"
            | "SYSTEMS_DEEP_CWE_PROMPT"
            | "threatModelRef"
            | "thinkingLevel"
            | "allowanceRef"
    )
}

pub(super) fn canonical(input: &Value) -> Result<Value> {
    let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let canonical = registry.prepare_tool_input(TOOL, input.clone(), None)?;
    let fields = canonical
        .as_object()
        .context("CWE proposal input must be an object")?;
    for name in fields.keys() {
        anyhow::ensure!(cwe_proposal_option_supported(name),
            "{name} is unsupported by standalone CWE proposals; remove this option. No model request started");
    }
    Ok(canonical)
}

impl Limits {
    pub fn parse(input: &Value) -> Result<Self> {
        Ok(Self {
            source: SourcePrefixLimits {
                max_files: positive_usize(input, &["maxFiles"], 80)?,
                max_bytes: positive_usize(input, &["maxSourceBytes"], 160 * 1024)?,
                max_file_bytes: positive_usize(input, &["headBytes"], 2048)?,
            },
            max_classes: positive_usize(input, &["maxCweClasses"], 6)?,
            include_non_production: input["includeNonProduction"].as_bool().unwrap_or(false),
        })
    }
}

#[cfg(test)]
pub(super) fn legacy_input(input: &Value) -> Result<Value> {
    let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let tool = registry
        .resolve_tool(TOOL)
        .context("CWE proposal descriptor missing")?;
    let allowed = tool
        .options
        .iter()
        .filter(|option| cwe_proposal_option_supported(&option.name))
        .flat_map(|option| {
            std::iter::once(option.name.as_str()).chain(option.aliases.iter().map(String::as_str))
        })
        .chain(std::iter::once("allowanceRef"))
        .collect::<BTreeSet<_>>();
    let fields = input
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| allowed.contains(name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    Ok(Value::Object(fields))
}
