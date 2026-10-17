use super::*;
use crate::workspace::inventory::SourcePrefixLimits;

pub(crate) fn deep_discovery_option_supported(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "model"
            | "maxFiles"
            | "maxSourceBytes"
            | "maxSnapshotBytes"
            | "headBytes"
            | "maxFindings"
            | "maxCweClasses"
            | "includeNonProduction"
            | "cwes"
            | "artifactDir"
            | "SYSTEMS_DEEP_HUNT_PROMPT"
            | "threatModelRef"
            | "scanContextRef"
            | "scanScopeRef"
            | "thinkingLevel"
            | "allowanceRef"
    )
}

pub(super) fn canonical(input: &Value) -> Result<Value> {
    let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = registry.prepare_tool_input(TOOL, input.clone(), None)?;
    for name in input
        .as_object()
        .context("Deep discovery input must be an object")?
        .keys()
    {
        anyhow::ensure!(
            deep_discovery_option_supported(name),
            "{name} is unsupported by source-only deep discovery; remove it before model work"
        );
    }
    Ok(input)
}

pub(super) struct Limits {
    pub source: SourcePrefixLimits,
    pub max_findings: usize,
    pub max_snapshot_bytes: usize,
    pub include_non_production: bool,
}

impl Limits {
    pub fn parse(input: &Value) -> Result<Self> {
        Ok(Self {
            source: SourcePrefixLimits {
                max_files: positive_usize(input, &["maxFiles"], 80)?,
                max_bytes: positive_usize(input, &["maxSourceBytes"], 160 * 1024)?,
                max_file_bytes: positive_usize(input, &["headBytes"], 2048)?,
            },
            max_findings: positive_usize(input, &["maxFindings"], 10)?,
            max_snapshot_bytes: positive_usize(input, &["maxSnapshotBytes"], 16 * 1024 * 1024)?,
            include_non_production: input["includeNonProduction"].as_bool().unwrap_or(false),
        })
    }
}

pub(super) fn classes(input: &Value) -> Result<Vec<DeepSemanticCweSelection>> {
    let maximum = SystemsHuntInput::from_tool_input(input)?.max_cwe_classes;
    let supplied=input["cwes"].as_array().context(
        "Explicit cwes[] are required. Inspect a CWE proposal and select classes before approving this separate discovery action; no implicit selection request starts")?;
    anyhow::ensure!(
        !supplied.is_empty(),
        "Select at least one explicit CWE class before discovery"
    );
    let classes = supplied
        .iter()
        .map(|value| match value.as_str() {
            Some(id) => json!({"id":id,"name":id,"reason":"Explicit operator selection"}),
            None => value.clone(),
        })
        .collect::<Vec<_>>();
    super::super::cwe_proposal::validate_classes(&json!({"cwes":classes}), maximum)
}
