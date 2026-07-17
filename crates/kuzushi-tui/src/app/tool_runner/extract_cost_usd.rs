pub(crate) fn extract_cost_report(
    result: &serde_json::Value,
) -> anyhow::Result<kuzushi_core::runtime::RuntimeCostReport> {
    kuzushi_core::run_artifacts::tool_run_output_cost_report(result)
}
