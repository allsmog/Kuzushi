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
                ToolPhase::Report,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
            report_sarif_tool().with_policy(target_write_policy(
                ToolPhase::Report,
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
        vec![
            opt(
                "output",
                OptionType::Path,
                "Output SARIF path. Relative paths resolve under the workspace \
                 root; default .kuzushi/v3/reports/confirmed-findings.sarif.",
            )
            .aliases(&["path", "out"])
            .target_write(),
            opt(
                "campaignId",
                OptionType::String,
                "Export only this study's confirmed observations and embed its \
                 investigation receipt. Omit for workspace history.",
            )
            .aliases(&["campaign_id"]),
        ],
    )
}

pub(in crate::modules) fn build_report_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let run_id = string_input_any(input, &["runId", "run_id"]);
    let report = crate::report::build_run_report_with_source_filter(
        &target,
        run_id.as_deref(),
        &is_analysis_tool,
    )?;
    Ok(report.to_tool_json())
}

/// Exports and read-only listings describe existing results, so the implicit
/// latest run is never one of them. Classification comes from the registered
/// descriptors that shared dispatch also uses.
fn is_analysis_tool(tool: &str) -> bool {
    use super::autonomy::{classify, ToolClassification};
    !matches!(
        classify(tool),
        Some(ToolClassification::Report | ToolClassification::Read)
    )
}

pub(in crate::modules) fn run_report_sarif_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("report:sarif requires an active workspace target")?;
    let store = ctx
        .findings_store
        .context("report:sarif requires a findings store")?;
    let receipt = string_input_any(input, &["campaignId", "campaign_id"])
        .map(|campaign| crate::workspace::load_investigation_report(workspace, campaign.trim()))
        .transpose()?;
    let findings = match &receipt {
        Some(receipt) => {
            store.list_distinct_findings_for_scan_ids(&receipt.observation_run_refs)?
        }
        None => store.list_all_findings()?,
    };
    let records = store.list_review_decisions_for_findings(&findings)?;
    let selection = crate::report::ConfirmedSarifSelection {
        findings: &findings,
        records: &records,
        investigation: receipt.as_ref(),
    };
    crate::report::export_confirmed_sarif(workspace.root(), input, &selection)
}

pub(in crate::modules) fn execute_report_build_tool(
    _registry: &ModuleRegistry,
    _name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    build_report_tool(input, ctx)
}

pub(in crate::modules) fn execute_report_sarif_tool(
    _registry: &ModuleRegistry,
    _name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    run_report_sarif_tool(input, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_artifacts::{write_run_summary, RunSummary};

    fn completed(target: &std::path::Path, run_id: &str, tool: &str, at: u64) {
        let mut summary = RunSummary::running(
            run_id,
            "tool",
            Some(tool.to_string()),
            target.display().to_string(),
        )
        .complete();
        summary.completed_at_unix = Some(at);
        write_run_summary(target, &summary).unwrap();
    }

    #[test]
    fn latest_report_source_skips_later_export_and_read_only_runs() {
        let temp = tempfile::tempdir().unwrap();
        completed(temp.path(), "a-scan", "secret-scan:scan", 100);
        for (run_id, tool) in [
            ("b-export", "workspace:export-findings"),
            ("c-listing", "findings:list"),
            ("d-sarif", "report:sarif"),
        ] {
            completed(temp.path(), run_id, tool, 200);
        }
        let workspace = crate::WorkspaceTarget::new(temp.path()).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let implicit = build_report_tool(&json!({}), &ctx).unwrap();
        assert_eq!(implicit["data"]["sourceRunId"], "a-scan", "{implicit:#}");

        let explicit = build_report_tool(&json!({"runId": "b-export"}), &ctx).unwrap();
        assert_eq!(explicit["data"]["sourceRunId"], "b-export");
    }
}
