use kuzushi_core::run_artifacts::tool_run_output_cost_usd;

pub(crate) fn extract_cost_usd(result: &serde_json::Value) -> Option<f64> {
    tool_run_output_cost_usd(result)
}
