use anyhow::Result;
use kuzushi_core::review_yield::application::ScoredIdentity;
use kuzushi_core::review_yield::domain::{ReviewYieldSignal, ValidatedReviewYieldModel};
use serde_json::{json, Value};

/// Advisory framing, repeated wherever a score is shown. The signal informs an
/// operator; it never reorders, filters, or hides a review.
const ADVISORY_NOTE: &str = "advisory signal; does not change review order";

pub(crate) fn review_yield_model_output(
    model: &ValidatedReviewYieldModel,
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&model_json(model))?
        ));
    }
    let lines = model_lines(model);
    Ok(format!("{}\n", lines.join("\n")))
}

fn model_lines(model: &ValidatedReviewYieldModel) -> Vec<String> {
    vec![
        "Review-yield model".to_string(),
        row("Model id", model.model_id()),
        row("Task", model.task_id()),
        row("Feature schema", model.feature_schema_id()),
        row("Label policy", model.label_policy_id()),
        row("Nodes", &model.node_count().to_string()),
        row("Depth", &model.depth().to_string()),
        row(
            "Minimum leaf support",
            &model.minimum_leaf_support().to_string(),
        ),
        row(
            "Maximum unknown categories",
            &model.maximum_unknown_categories().to_string(),
        ),
    ]
}

fn model_json(model: &ValidatedReviewYieldModel) -> Value {
    json!({
        "modelId": model.model_id(),
        "taskId": model.task_id(),
        "featureSchemaId": model.feature_schema_id(),
        "labelPolicyId": model.label_policy_id(),
        "nodeCount": model.node_count(),
        "depth": model.depth(),
        "minimumLeafSupport": model.minimum_leaf_support(),
        "maximumUnknownCategories": model.maximum_unknown_categories(),
    })
}

pub(crate) fn review_yield_score_output(
    model: &ValidatedReviewYieldModel,
    scores: &[ScoredIdentity],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&score_json(model, scores))?
        ));
    }
    Ok(score_plain(model, scores))
}

fn score_json(model: &ValidatedReviewYieldModel, scores: &[ScoredIdentity]) -> Value {
    let rows: Vec<Value> = scores
        .iter()
        .map(|scored| json!({"finding": scored.identity_id, "signal": scored.signal}))
        .collect();
    json!({"advisory": ADVISORY_NOTE, "modelId": model.model_id(), "scores": rows})
}

fn score_plain(model: &ValidatedReviewYieldModel, scores: &[ScoredIdentity]) -> String {
    let mut lines = vec![
        format!("Review-yield scores ({ADVISORY_NOTE})"),
        row("Model id", model.model_id()),
        row("Scored findings", &scores.len().to_string()),
    ];
    lines.extend(scores.iter().map(score_line));
    lines.push(next_step(scores));
    format!("{}\n", lines.join("\n"))
}

/// One grep-friendly line per finding: identity, why it is or is not scored,
/// and the numbers behind an eligible score.
fn score_line(scored: &ScoredIdentity) -> String {
    let signal = &scored.signal;
    let suffix = match signal.is_eligible() {
        true => eligible_detail(signal),
        false => signal.eligibility.detail(),
    };
    format!(
        "{:<40}{:<26}{suffix}",
        scored.identity_id,
        signal.eligibility.kind()
    )
}

fn eligible_detail(signal: &ReviewYieldSignal) -> String {
    let (low, high) = signal.credible_interval_95.unwrap_or_default();
    let support =
        signal.positive_count.unwrap_or_default() + signal.negative_count.unwrap_or_default();
    format!(
        "rate {:.3}  ci {low:.3}-{high:.3}  support {support}  entropy {:.3}  path {}",
        signal.smoothed_positive_rate.unwrap_or_default(),
        signal.leaf_entropy_bits.unwrap_or_default(),
        signal.rendered_path().join(" -> ")
    )
}

fn next_step(scores: &[ScoredIdentity]) -> String {
    if scores.is_empty() {
        return "Next: run a scan against this target so there are findings to score.".to_string();
    }
    "Next: review these findings yourself; the score is advisory only.".to_string()
}

fn row(label: &str, value: &str) -> String {
    format!("{label:<30}{value}")
}
