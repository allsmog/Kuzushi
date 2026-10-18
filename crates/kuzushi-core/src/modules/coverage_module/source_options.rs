use super::*;
use crate::workspace::coverage_ledger::{SourceComparisonBudget, SourceComparisonLimits};
use std::path::Path;

pub(super) fn source_options(mut options: Vec<OptionSpec>) -> Vec<OptionSpec> {
    let defaults = SourceComparisonLimits::default();
    options.extend([
        opt("maxSourceComparisons", OptionType::Int,
            "Maximum historical Git diff requests, including skip revalidation. Reaching the limit stops without new baseline writes.")
            .default(json!(defaults.max_comparisons)).integer_range(1, 512),
        opt("maxDiffBytes", OptionType::Int,
            "Maximum aggregate Git diff stdout bytes across initial comparison and revalidation. Not a total RAM or dollar ceiling. Per-command limits also apply.")
            .default(json!(defaults.max_diff_bytes)).integer_range(1, 67_108_864),
    ]);
    options
}

pub(super) fn source_budget(input: &Value) -> Result<SourceComparisonBudget> {
    let limits = serde_json::from_value(json!({
        "maxComparisons":input["maxSourceComparisons"], "maxDiffBytes":input["maxDiffBytes"]
    }))?;
    SourceComparisonBudget::new(limits)
}

pub(super) fn requested_source_comparison(
    input: &Value,
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
    budget: &mut SourceComparisonBudget,
) -> Result<Option<SweepReport>> {
    if input["compareSource"].as_bool() != Some(true) {
        return Ok(None);
    }
    sweep_target_with_budget(target, ctx.cancellation, budget).map(Some)
}

pub(super) fn source_comparison_label(performed: bool) -> &'static str {
    if performed {
        "historical source comparison performed; complete coverage and finding fixes remain unverified"
    } else {
        "saved evidence only; current source not checked. Use compareSource=true for a bounded comparison"
    }
}
