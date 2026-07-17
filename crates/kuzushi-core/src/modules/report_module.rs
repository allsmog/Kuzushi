use super::*;

pub(crate) fn report_module() -> BuiltinModule {
    builtin_module(
        "report",
        "Report",
        ModuleKind::Defense,
        "Build artifact-backed Kuzushi run reports without executing scanners or runtimes.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Fix,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "report:build",
                "Build a Markdown report from canonical run artifacts.",
                vec![
                target_option(),
                opt("runId", OptionType::String, "Run id to report.")
                    .aliases(&["run_id"])
                    .advanced(),
                ],
            )],
        ),
        vec![],
    )
}
