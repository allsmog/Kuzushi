use super::*;

impl SystemsHuntInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
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
        })
    }
}
