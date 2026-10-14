use super::*;

pub(crate) fn read_x_ray(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let mut report = read_x_ray_report_artifacts(&target, Some(&repo_name), "rust", 0.0)?;
    ctx.ensure_active()?;
    report.cost_usd_exact = false;
    let mut data = json!(report);
    data["readProvenance"] = json!({"schemaVersion":1,"sourceFreshness":"not-assessed",
        "generationSpend":"unknown","producerRuntime":"unknown","producerModel":"unknown",
        "scanContext":"unknown","securityVerdictAssessed":false,"readerProviderCalls":0,
        "artifactLimitBytes":8 * 1024 * 1024,"architectureContentValidated":false});
    let mut result = x_ray_response(
        render_x_ray_read_summary(&report),
        data,
        &report,
        crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
    )?;
    result["warnings"] = json!(["Stored report claims are unassessed. Source freshness and original generation spend are unknown. Reading these artifacts does not accept Map or establish a finding verdict."]);
    Ok(result)
}
