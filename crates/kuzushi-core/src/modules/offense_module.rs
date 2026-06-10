use super::*;
use crate::modules::registry::ToolDispatchResult;

/// The live-target offense module. Today it exposes `offense:chain`, which
/// runs an operator-authored attack chain against an authorized target. Every
/// play clears the engagement-scope gate before any traffic is sent.
pub(crate) fn offense_module() -> BuiltinModule {
    builtin_module(
        "offense",
        "Offense",
        ModuleKind::Offense,
        "Authorized live-target operations: run declarative attack chains (auth-bypass -> IDOR -> RCE) against a host the engagement scope allows.",
        vec![offense_chain_tool()],
        vec![],
    )
}

fn offense_chain_tool() -> ToolDescriptor {
    tool_with_options(
        "offense:chain",
        "Run a declarative attack chain against an authorized target. Requires an engagement scope (.kuzushi/engagement-scope.json or inline) that allows the target; a denied target never sends traffic.",
        vec![
            opt("target", OptionType::String, "Target host (IP or hostname) to operate against.")
                .aliases(&["targetHost", "target_host"])
                .required(),
            opt(
                "chain",
                OptionType::Json,
                "Inline chain spec: {name, plays:[{name, method?, path, headers?, body?, expectStatus?, expectSignals?}]}.",
            ),
            opt(
                "chainFile",
                OptionType::String,
                "Name of a chain spec under .kuzushi/plays/<name>.json (used when 'chain' is absent).",
            )
            .aliases(&["chain_file", "play"]),
            opt(
                "scope",
                OptionType::Json,
                "Inline engagement scope; overrides .kuzushi/engagement-scope.json.",
            )
            .advanced(),
            opt("timeoutMs", OptionType::Int, "Per-play network timeout in milliseconds.")
                .aliases(&["timeout_ms"])
                .default(json!(15000))
                .advanced(),
            opt("runId", OptionType::String, "Run id to record chain evidence under.")
                .aliases(&["run_id"])
                .advanced(),
        ],
    )
}

pub(in crate::modules) fn dispatch_offense_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> ToolDispatchResult {
    match name {
        "offense:chain" => Some(run_offense_chain(input, ctx)),
        _ => None,
    }
}

fn run_offense_chain(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "offense:chain needs an active workspace for the engagement scope. Pass --target <dir> or start the shell with --target.",
    )?;
    Ok(crate::offense::execute_offense_chain(input, workspace.root()))
}
