use super::*;

use crate::modules::registry::ToolExecutor;

#[derive(Debug, Clone, Copy, Default)]
pub(in crate::modules) struct PluginAdapterVisibility {
    pub(in crate::modules) shinsa: bool,
    pub(in crate::modules) tob: bool,
    pub(in crate::modules) vuln_scout: bool,
}

pub(in crate::modules) fn register_modules(
    registry: &mut ModuleRegistry,
    executor: ToolExecutor,
    visibility: PluginAdapterVisibility,
) {
    registry.register(wasm_plugin_module().with_executor(executor));
    registry.register(visible_when(
        vuln_scout_module().with_executor(executor),
        visibility.vuln_scout,
    ));
    registry.register(visible_when(
        tob_module().with_executor(executor),
        visibility.tob,
    ));
    registry.register(visible_when(
        shinsa_module().with_executor(executor),
        visibility.shinsa,
    ));
}

fn visible_when(module: BuiltinModule, visible: bool) -> BuiltinModule {
    if visible {
        module
    } else {
        module.deferred()
    }
}

pub(in crate::modules) fn execute_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match tool_name {
        "wasm-plugin:analyze" => run_wasm_plugin_analyze(input, ctx),
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
            "Run the optional Vuln Scout whitebox-audit plugin against the target repository.",
            vec![target_option(), plugin_root_option(), model_option()],
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
                vec![
                    target_option(),
                    plugin_root_option(),
                    opt(
                        "skills",
                        OptionType::StringList,
                        "Trail of Bits skill subset.",
                    )
                    .advanced(),
                    model_option(),
                ],
            ),
            tool("tob:skills", "List available Trail of Bits skill modules."),
        ],
        vec![dag("tob:audit", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn plugin_root_option() -> OptionSpec {
    opt(
        "pluginRoot",
        OptionType::Path,
        "Installed plugin root path.",
    )
    .aliases(&["pluginPath", "plugin_root", "plugin_path"])
    .advanced()
}
