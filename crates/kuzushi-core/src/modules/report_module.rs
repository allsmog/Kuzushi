use super::*;

pub(crate) fn report_module() -> BuiltinModule {
    builtin_module(
        "report",
        "Report",
        ModuleKind::Defense,
        "Build artifact-backed Kuzushi run reports without executing scanners or runtimes.",
        vec![
            tool_with_options(
                "report:build",
                "Build a Markdown report from canonical run artifacts.",
                vec![
                    target_option(),
                    opt("runId", OptionType::String, "Run id to report.")
                        .aliases(&["run_id"])
                        .advanced(),
                ],
            )
            .with_policy(workspace_policy(
                ToolPhase::Fix,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
            report_sarif_tool().with_policy(target_write_policy(
                ToolPhase::Fix,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
        ],
        vec![],
    )
}

fn report_sarif_tool() -> ToolDescriptor {
    tool_with_options(
        "report:sarif",
        "Export findings whose latest review decision confirms them \
         (confirmed or to-fix) as SARIF 2.1.0, with rules derived from CWE \
         ids and the workspace trend object carried as run properties. \
         Deterministic; no model calls.",
        vec![opt(
            "output",
            OptionType::Path,
            "Output SARIF path. Relative paths resolve under the workspace \
             root; default .kuzushi/v3/reports/confirmed-findings.sarif.",
        )
        .aliases(&["path", "out"])
        .target_write()],
    )
}

pub(in crate::modules) fn execute_report_sarif_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("report:sarif requires an active workspace target")?;
    let store = ctx
        .findings_store
        .context("report:sarif requires a findings store")?;
    let findings = store.list_all_findings()?;
    let records = store.list_review_decisions_for_findings(&findings)?;
    crate::report::export_confirmed_sarif(workspace.root(), input, &findings, &records)
}
