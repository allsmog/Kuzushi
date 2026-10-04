use super::*;

/// Defaults describe this approved action, not a runtime or model fallback.
fn fixed_options() -> Value {
    json!({"pipeline":"single","mode":"build","seedMode":"fresh","newModel":true,
        "activate":false,"sources":["source-code"],"variantScan":false,"emitFindings":false,
        "offline":true,"preserveUserEdits":false})
}

pub(super) fn prepare(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Value> {
    let mut input = input.clone();
    let object = input
        .as_object_mut()
        .context("contextInput must be an object")?;
    for (key, value) in fixed_options().as_object().unwrap() {
        object.entry(key.clone()).or_insert_with(|| value.clone());
    }
    let prepared = registry.prepare_dispatch_input(TOOL, input, ctx, None)?;
    let mut input = prepared.value().clone();
    validate(&input)?;
    let root = ctx
        .workspace
        .context("context study requires a workspace")?
        .root();
    let target = input["target"]
        .as_str()
        .context("context study target is missing")?;
    anyhow::ensure!(
        std::fs::canonicalize(target)? == std::fs::canonicalize(root)?,
        "context study must use its investigation repository"
    );
    let model = crate::tool_execution_model(TOOL, &input, ctx.config)
        .context("Select a model before planning context generation")?;
    input["model"] = json!(model);
    input
        .as_object_mut()
        .unwrap()
        .entry("THREAT_MODEL_PROMPT")
        .or_insert_with(|| json!(crate::capabilities::threat_model::DEFAULT_THREAT_MODEL_GUIDANCE));
    Ok(input)
}

pub(super) fn validate(input: &Value) -> Result<()> {
    for (key, value) in fixed_options().as_object().unwrap() {
        anyhow::ensure!(
            input.get(key) == Some(value),
            "context study requires {key}={value}; additional work needs a separate plan"
        );
    }
    for key in [
        "allowanceRef",
        "modelId",
        "scope",
        "seed",
        "designDocs",
        "vulnsFile",
        "outputDir",
        "advisoryFixtures",
    ] {
        anyhow::ensure!(input.get(key).is_none(), "context study does not accept {key}; this action generates a fresh repository-wide draft from source");
    }
    Ok(())
}
