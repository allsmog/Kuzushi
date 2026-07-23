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
        "randori:threat-model" => read_threat_model(input, ctx, ReadFlavor::Randori),
        "threat-model:methodologies" => Ok(methodologies_output()),
        other => anyhow::bail!("unknown threat-model tool {other:?}"),
    }
}
