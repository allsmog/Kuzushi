use super::*;
use serde_json::Value;

pub(super) fn rows(artifact: &JsonFileState) -> Vec<RecommendationDetailRow> {
    let JsonFileState::Present(value) = artifact else {
        return Vec::new();
    };
    let report = recommendation_report_value(value);
    let Some(mode) = report["rankingMode"].as_str() else {
        return Vec::new();
    };
    let mut rows = vec![recommendation_detail_row(
        "ranking",
        ranking_label(mode, report),
    )];
    rows.extend(inventory_rows(report));
    if mode == "model" {
        rows.push(recommendation_detail_row("cost", cost_label(report)));
    }
    rows
}

fn ranking_label(mode: &str, report: &Value) -> String {
    match mode {
        "deterministic" => "deterministic; no model request".into(),
        "model" => format!(
            "selected model: {}",
            report["model"].as_str().unwrap_or("not recorded")
        ),
        _ => "not recorded".into(),
    }
}

fn inventory_rows(report: &Value) -> Vec<RecommendationDetailRow> {
    let Some(coverage) = report.get("inventoryCoverage") else {
        return Vec::new();
    };
    vec![
        recommendation_detail_row(
            "inventory",
            format!(
                "{}; {} entries; {} clipped files; {} omitted paths",
                coverage["status"].as_str().unwrap_or("unknown"),
                count(coverage, "entries"),
                count(coverage, "truncatedFiles"),
                count(coverage, "omittedPaths")
            ),
        ),
        recommendation_detail_row(
            "coverage",
            "Full repository coverage is not established.".into(),
        ),
    ]
}

fn count(value: &Value, name: &str) -> String {
    value[name]
        .as_u64()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn cost_label(report: &Value) -> String {
    if report["costUsdExact"].as_bool() != Some(true) {
        return "dollar cost unknown; inspect the shared investigation account".into();
    }
    report["costUsd"]
        .as_f64()
        .map(|cost| format!("reported ${cost:.4}; inspect the shared investigation account"))
        .unwrap_or_else(|| "dollar cost unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn partial_inventory_is_visible_without_claiming_complete_coverage() {
        let artifact = JsonFileState::Present(
            json!({"data":{"recommendations":[],"rankingMode":"deterministic",
            "inventoryCoverage":{"status":"partial","entries":12,"truncatedFiles":1,"omittedPaths":2}}}),
        );
        let rows = rows(&artifact);
        assert_eq!(rows[0].cells[1], "deterministic; no model request");
        assert!(rows[1].cells[1].contains("partial; 12 entries; 1 clipped files; 2 omitted paths"));
        assert!(rows[2].cells[1].contains("not established"));
    }

    #[test]
    fn unknown_model_cost_never_renders_as_zero() {
        let artifact =
            JsonFileState::Present(json!({"data":{"recommendations":[],"rankingMode":"model",
            "model":"openai-codex:gpt-5.5","costUsd":0.0,"costUsdExact":false}}));
        let rows = rows(&artifact);
        assert!(rows[0].cells[1].contains("openai-codex:gpt-5.5"));
        assert!(rows[1].cells[1].contains("unknown"));
        assert!(!rows[1].cells[1].contains("$0"));
    }

    #[test]
    fn legacy_artifacts_keep_existing_rows_without_invented_metadata() {
        assert!(rows(&JsonFileState::Present(json!({"recommendations":[]}))).is_empty());
    }
}
