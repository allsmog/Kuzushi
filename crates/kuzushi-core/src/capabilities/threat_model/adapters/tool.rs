use super::*;

pub fn execute_threat_model_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "threat-model:build" => build_threat_model(input, ctx, runtime, BuildFlavor::ThreatModel),
        "randori:pasta" => build_threat_model(input, ctx, runtime, BuildFlavor::RandoriPasta),
        "threat-model:read" => read_threat_model(input, ctx, ReadFlavor::ThreatModel),
        "threat-model:verify" => verify_threat_model_adapter(input, ctx),
        "threat-model:import" => import_threat_model_adapter(input, ctx),
        "threat-model:models" => list_threat_models_adapter(ctx),
        "threat-model:activate" => activate_threat_model_adapter(input, ctx),
        "threat-model:revisions" => list_threat_model_revisions_adapter(input, ctx),
        "threat-model:diff" => diff_threat_model_revisions_adapter(input, ctx),
        "threat-model:restore" => restore_threat_model_revision_adapter(input, ctx),
        "threat-model:adopt" => adopt_threat_model_mirror_adapter(ctx),
        "randori:threat-model" => read_threat_model(input, ctx, ReadFlavor::Randori),
        "threat-model:methodologies" => Ok(methodologies_output()),
        other => anyhow::bail!("unknown threat-model tool {other:?}"),
    }
}
