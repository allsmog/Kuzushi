use super::*;

impl SystemsHuntInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        let prompts = SystemsPromptInput::from_tool_input(input)?;
        Ok(Self {
            max_findings: positive_usize(input, &["maxFindings", "max_findings"], 30)?,
            max_surfaces: positive_usize(input, &["maxSurfaces", "max_surfaces"], 50)?,
            max_files: positive_usize(input, &["maxFiles", "max_files"], 5000)?,
            head_bytes: positive_usize(input, &["headBytes", "head_bytes"], 16384)?,
            include_non_production: bool_option(
                input,
                &["includeNonProduction", "include_non_production"],
                false,
            )?,
            max_trigger_hypotheses_per_surface: positive_usize(
                input,
                &[
                    "maxTriggerHypothesesPerSurface",
                    "max_trigger_hypotheses_per_surface",
                ],
                3,
            )?,
            max_cwe_classes: positive_usize(input, &["maxCweClasses", "max_cwe_classes"], 6)?,
            artifact_dir: optional_nonempty_string(input, "artifactDir")?
                .or(optional_nonempty_string(input, "artifact_dir")?)
                .unwrap_or_else(|| ".kuzushi/systems-hunt".to_string()),
            model: optional_nonempty_string(input, "model")?,
            invariant_system_prompt: prompts.invariant,
            trigger_system_prompt: prompts.trigger,
            hunt_system_prompt: prompts.hunt,
            deep_semantic_cwe_system_prompt: prompts.deep_cwe,
            deep_semantic_hunt_system_prompt: prompts.deep_hunt,
        })
    }
}

struct SystemsPromptInput {
    invariant: String,
    trigger: String,
    hunt: String,
    deep_cwe: String,
    deep_hunt: String,
}

impl SystemsPromptInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            invariant: prompt_or_default(
                input,
                "SYSTEMS_INVARIANT_PROMPT",
                SYSTEMS_INVARIANT_SYSTEM_PROMPT,
            )?,
            trigger: prompt_or_default(
                input,
                "SYSTEMS_TRIGGER_PROMPT",
                SYSTEMS_TRIGGER_SYSTEM_PROMPT,
            )?,
            hunt: prompt_or_default(input, "SYSTEMS_HUNT_PROMPT", SYSTEMS_HUNT_SYSTEM_PROMPT)?,
            deep_cwe: prompt_or_default(
                input,
                "SYSTEMS_DEEP_CWE_PROMPT",
                DEEP_SEMANTIC_CWE_SYSTEM_PROMPT,
            )?,
            deep_hunt: prompt_or_default(
                input,
                "SYSTEMS_DEEP_HUNT_PROMPT",
                DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT,
            )?,
        })
    }
}

fn prompt_or_default(input: &Value, key: &str, default: &str) -> Result<String> {
    Ok(optional_nonempty_string(input, key)?.unwrap_or_else(|| default.to_string()))
}
