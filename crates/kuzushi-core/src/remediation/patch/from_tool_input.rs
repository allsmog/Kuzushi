use super::*;

#[derive(Debug, Clone)]
pub(crate) struct PatchFindingInput {
    pub(crate) fingerprint: String,
    pub(crate) max_iterations: usize,
    pub(crate) build_cmd: Option<String>,
    pub(crate) test_cmd: Option<String>,
}

impl PatchFindingInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            fingerprint: patch_finding_fingerprint(input)?,
            max_iterations: patch_finding_max_iterations(input)?,
            build_cmd: optional_string_alias(input, &["buildCmd", "buildCommand"])?,
            test_cmd: optional_string_alias(input, &["testCmd", "testCommand"])?,
        })
    }
}

fn patch_finding_fingerprint(input: &Value) -> Result<String> {
    let Some(value) = input.get("fingerprint") else {
        anyhow::bail!("patch:finding requires a fingerprint");
    };
    parse_patch_finding_fingerprint(value)
}

fn parse_patch_finding_fingerprint(value: &Value) -> Result<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => anyhow::bail!("patch:finding fingerprint must be a non-empty string"),
    }
}

fn patch_finding_max_iterations(input: &Value) -> Result<usize> {
    match input
        .get("maxIterations")
        .or_else(|| input.get("max_iterations"))
    {
        Some(value) => parse_patch_finding_max_iterations(value),
        None => Ok(3),
    }
}

fn parse_patch_finding_max_iterations(value: &Value) -> Result<usize> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .context("patch:finding maxIterations must be a positive integer")
            .map(clamped_patch_iterations),
        Value::String(value) => value
            .parse::<usize>()
            .context("patch:finding maxIterations must be a positive integer")
            .map(clamped_patch_iterations),
        _ => anyhow::bail!("patch:finding maxIterations must be a positive integer"),
    }
}

fn clamped_patch_iterations<T: TryInto<usize>>(value: T) -> usize {
    value.try_into().ok().unwrap_or(1).clamp(1, 10)
}

#[derive(Debug, Clone)]
pub(crate) struct PatchValidationPlan {
    pub(crate) build: Option<String>,
    pub(crate) test: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PatchSynthesis {
    pub(crate) diff: String,
    pub(crate) explanation: String,
}

pub(crate) const PATCH_SYSTEM_PROMPT: &str = r#"You are Kuzushi's security patch generator.
Return only JSON matching:
{"diff":"unified diff with a/ and b/ paths","explanation":"short explanation"}."#;
