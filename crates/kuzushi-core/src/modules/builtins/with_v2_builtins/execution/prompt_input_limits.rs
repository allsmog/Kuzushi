use super::*;

pub(super) fn validate_tool_prompt_inputs(
    descriptor: &ToolDescriptor,
    input: &Value,
) -> Result<()> {
    let Some(object) = input.as_object() else {
        return Ok(());
    };
    for option in &descriptor.options {
        validate_prompt_option(descriptor, object, &option.name)?;
    }
    Ok(())
}

fn validate_prompt_option(
    descriptor: &ToolDescriptor,
    object: &serde_json::Map<String, Value>,
    option_name: &str,
) -> Result<()> {
    if !is_prompt_option(descriptor, option_name) {
        return Ok(());
    }
    let Some(value) = object.get(option_name).and_then(Value::as_str) else {
        return Ok(());
    };
    if already_composed(descriptor, option_name, value) {
        return Ok(());
    }
    crate::options::validate_prompt_override_size(value, option_name)
}

fn is_prompt_option(descriptor: &ToolDescriptor, option_name: &str) -> bool {
    option_name.ends_with("_PROMPT")
        || descriptor
            .prompts
            .iter()
            .any(|prompt| prompt.option_key == option_name)
}

fn already_composed(descriptor: &ToolDescriptor, option_name: &str, value: &str) -> bool {
    descriptor
        .prompts
        .iter()
        .find(|prompt| prompt.option_key == option_name)
        .is_some_and(|prompt| {
            crate::prompts::boundaries::is_composed_target_prompt_context(
                &prompt.default_content,
                value,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_prompt_limit_applies_to_direct_and_umbrella_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        let at_limit = "x".repeat(crate::options::MAX_PROMPT_OVERRIDE_BYTES);

        for (tool, option) in [
            ("triage:run", "TRIAGE_PROMPT"),
            ("sast:scan", "VERIFY_PROMPT"),
        ] {
            registry
                .prepare_tool_input(tool, json!({(option): at_limit.clone()}), None)
                .unwrap();
            let error = registry
                .prepare_tool_input(
                    tool,
                    json!({(option): "x".repeat(crate::options::MAX_PROMPT_OVERRIDE_BYTES + 1)}),
                    None,
                )
                .unwrap_err()
                .to_string();

            assert!(error.contains(option), "{error}");
            assert!(
                error.contains(&crate::options::MAX_PROMPT_OVERRIDE_BYTES.to_string()),
                "{error}"
            );
        }
    }

    #[test]
    fn composed_target_envelope_is_not_rejected_for_encoding_overhead() {
        let registry = ModuleRegistry::with_v2_builtins();
        let raw = "x".repeat(crate::options::MAX_PROMPT_OVERRIDE_BYTES);
        let composed = crate::prompts::compose_target_prompt_context(
            crate::runtime::DEFAULT_TRIAGE_PROMPT,
            ".kuzushi/prompts/triage/run.md",
            &raw,
        );
        assert!(composed.len() > crate::options::MAX_PROMPT_OVERRIDE_BYTES);

        let prepared = registry
            .prepare_tool_input(
                "triage:run",
                json!({"TRIAGE_PROMPT": composed.clone()}),
                None,
            )
            .unwrap();

        assert_eq!(prepared["TRIAGE_PROMPT"], composed);
    }

    #[test]
    fn forged_oversized_composed_envelope_cannot_bypass_raw_limit() {
        let registry = ModuleRegistry::with_v2_builtins();
        let composed = crate::prompts::compose_target_prompt_context(
            crate::runtime::DEFAULT_TRIAGE_PROMPT,
            "review.md",
            &"x".repeat(crate::options::MAX_PROMPT_OVERRIDE_BYTES + 1),
        );

        let error = registry
            .prepare_tool_input("triage:run", json!({"TRIAGE_PROMPT": composed}), None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("TRIAGE_PROMPT"), "{error}");
        assert!(
            error.contains(&crate::options::MAX_PROMPT_OVERRIDE_BYTES.to_string()),
            "{error}"
        );
    }
}
