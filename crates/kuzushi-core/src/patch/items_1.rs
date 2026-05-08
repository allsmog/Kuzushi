use super::prelude::*;
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
        let fingerprint = match input.get("fingerprint") {
            Some(Value::String(value)) if !value.trim().is_empty() => value.trim().to_string(),
            Some(_) => anyhow::bail!("patch:finding fingerprint must be a non-empty string"),
            None => anyhow::bail!("patch:finding requires a fingerprint"),
        };

        let max_iterations = match input
            .get("maxIterations")
            .or_else(|| input.get("max_iterations"))
        {
            Some(Value::Number(number)) => number
                .as_u64()
                .context("patch:finding maxIterations must be a positive integer")?
                .clamp(1, 10) as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .context("patch:finding maxIterations must be a positive integer")?
                .clamp(1, 10),
            Some(_) => anyhow::bail!("patch:finding maxIterations must be a positive integer"),
            None => 3,
        };

        Ok(Self {
            fingerprint,
            max_iterations,
            build_cmd: optional_string_alias(input, &["buildCmd", "buildCommand"])?,
            test_cmd: optional_string_alias(input, &["testCmd", "testCommand"])?,
        })
    }
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
