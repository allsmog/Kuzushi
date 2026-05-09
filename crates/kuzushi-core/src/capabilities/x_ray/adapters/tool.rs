use super::*;

pub fn execute_x_ray_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "x-ray:run" | "x-ray:x-ray" => run_x_ray(input, ctx, runtime),
        "x-ray:read" => read_x_ray(input, ctx),
        other => anyhow::bail!("unknown x-ray tool {other:?}"),
    }
}
