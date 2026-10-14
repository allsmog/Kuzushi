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

#[cfg(test)]
fn build_report_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    build_report_with_registry(&ModuleRegistry::with_v2_builtins(), input, ctx)
}

fn build_report_with_registry(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let run_id = string_input_any(input, &["runId", "run_id"]);
    let report =
        crate::report::build_run_report_with_source_filter(&target, run_id.as_deref(), &|tool| {
            is_analysis_tool(registry, tool)
        })?;
    Ok(report.to_tool_json())
}

/// Auxiliary actions cannot replace the implicit analysis source. Result
/// ownership and effect come from the same registry used for dispatch.
fn is_analysis_tool(registry: &ModuleRegistry, tool: &str) -> bool {
    use super::autonomy::{classify_descriptor, ToolClassification};
    let Some(descriptor) = registry.resolve_tool(tool) else {
        return true;
    };
    if !descriptor.phase_result {
        return false;
    }
    !matches!(
        classify_descriptor(descriptor),
        Some(ToolClassification::Report | ToolClassification::Read | ToolClassification::Operate)
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
        .map(|campaign| {
            crate::workspace::load_investigation_report_document(workspace, campaign.trim())
        })
        .transpose()?;
    let findings = match &receipt {
        Some(receipt) => store.list_distinct_findings_for_scan_ids_with_identity_policy(
            receipt.summary().observation_run_refs,
            crate::findings::IdentityFoldPolicy::UNRESOLVED_RUN_SCOPE,
        )?,
        None => store.list_all_findings()?,
    };
    let records = store.list_review_decisions_for_findings(&findings)?;
    let metadata =
        crate::workspace::read_workspace_finding_export_records(workspace, store, &findings)?;
    crate::report::export_confirmed_sarif_document(
        workspace.root(),
        input,
        &findings,
        &records,
        receipt.as_ref(),
        &metadata,
    )
}

pub(in crate::modules) fn execute_report_build_tool(
    registry: &ModuleRegistry,
    _name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    build_report_with_registry(registry, input, ctx)
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

    #[test]
    fn implicit_report_source_skips_campaign_tracking_runs() {
        let root = tempfile::tempdir().unwrap();
        completed(root.path(), "a-scan", "sast:scan", 100);
        for (run, tool) in [
            ("b-status", "campaign:status"),
            ("c-coverage", "campaign:coverage"),
        ] {
            completed(root.path(), run, tool, 200);
        }
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let report = build_report_tool(&json!({}), &ctx).unwrap();
        assert_eq!(report["data"]["sourceRunId"], "a-scan", "{report:#}");
    }

    #[test]
    fn implicit_report_source_skips_auxiliary_review_writes() {
        let root = tempfile::tempdir().unwrap();
        completed(root.path(), "a-scan", "sast:scan", 100);
        for (run, tool) in [
            ("b-add", "suppress:add"),
            ("c-list", "suppress:list"),
            ("d-remove", "suppress:remove"),
            ("e-relationship", "findings:relationship"),
            ("f-lesson", "findings:lesson-save"),
            ("g-dismissal", "findings:dismiss"),
        ] {
            completed(root.path(), run, tool, 200);
        }
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let report = build_report_tool(&json!({}), &ctx).unwrap();
        assert_eq!(report["data"]["sourceRunId"], "a-scan");
        let explicit = build_report_tool(&json!({"runId": "c-list"}), &ctx).unwrap();
        assert_eq!(explicit["data"]["sourceRunId"], "c-list");
    }
}
