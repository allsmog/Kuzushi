use super::*;
use crate::workspace::inventory::SourcePrefixLimits;

pub(super) struct Limits {
    pub source: SourcePrefixLimits,
    pub max_surfaces: usize,
    pub max_invariants: usize,
    pub include_non_production: bool,
}

pub(crate) fn invariant_draft_option_supported(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "model"
            | "context"
            | "maxSurfaces"
            | "maxFiles"
            | "maxSourceBytes"
            | "headBytes"
            | "maxInvariants"
            | "includeNonProduction"
            | "SYSTEMS_INVARIANT_PROMPT"
            | "threatModelRef"
            | "thinkingLevel"
            | "allowanceRef"
    )
}

pub(super) fn canonical(input: &Value) -> Result<Value> {
    let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let canonical = registry.prepare_tool_input(TOOL, input.clone(), None)?;
    for name in canonical
        .as_object()
        .context("Invariant draft input must be an object")?
        .keys()
    {
        anyhow::ensure!(invariant_draft_option_supported(name),
            "{name} is unsupported by standalone invariant drafts; remove this option. No model request started");
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
            max_surfaces: positive_usize(input, &["maxSurfaces"], 24)?,
            max_invariants: positive_usize(input, &["maxInvariants"], 8)?,
            include_non_production: input["includeNonProduction"].as_bool().unwrap_or(false),
        })
    }
}
