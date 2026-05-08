use super::*;

pub(in crate::modules) fn register_modules(registry: &mut ModuleRegistry) {
    registry.register(vuln_scout_module());
    registry.register(tob_module());
    registry.register(shinsa_module());
}

pub(in crate::modules) fn execute_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match tool_name {
        "vuln-scout:audit" => run_vuln_scout_audit(input, ctx, runtime),
        "tob:audit" => run_tob_audit(input, ctx, runtime),
        "tob:skills" => list_tob_skills(input),
        "shinsa:scan" | "shinsa:quick-check" | "shinsa:nist-scan" | "shinsa:nist-quick-check" => {
            run_shinsa_assessment(tool_name, input, ctx, runtime)
        }
        "shinsa:frameworks" => list_shinsa_frameworks(input),
        _ => anyhow::bail!("unknown plugin adapter tool {tool_name:?}"),
    }
}

pub(in crate::modules) fn vuln_scout_module() -> BuiltinModule {
    builtin_module(
        "vuln-scout",
        "Vuln Scout",
        ModuleKind::Offense,
        "Whitebox pentest wrapper around the @kuzushi/vuln-scout Claude Code plugin.",
        vec![tool_with_options(
            "vuln-scout:audit",
            "Run the Vuln Scout audit plugin.",
            vec![target_option(), model_option()],
        )],
        vec![dag("vuln-scout:audit", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn tob_module() -> BuiltinModule {
    builtin_module(
        "tob",
        "Trail of Bits Skills",
        ModuleKind::Offense,
        "Audit wrapper around the @kuzushi/tob-skills Claude Code plugin collection.",
        vec![
            tool_with_options(
                "tob:audit",
                "Run a Trail of Bits skills audit.",
                vec![target_option(), model_option()],
            ),
            tool("tob:skills", "List available Trail of Bits skill modules."),
        ],
        vec![dag("tob:audit", "findings", &["context:build"])],
    )
}
