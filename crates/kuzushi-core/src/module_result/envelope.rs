use serde_json::{json, Value};

pub(crate) fn completed_output_result(
    summary: impl Into<String>,
    output: impl Into<String>,
    data: Value,
) -> Value {
    json!({
        "ok": true,
        "status": "completed",
        "summary": summary.into(),
        "output": output.into(),
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "data": data,
    })
}

pub(crate) fn failed_output_result(
    summary: impl Into<String>,
    output: impl Into<String>,
    data: Value,
) -> Value {
    let summary = summary.into();
    let output = output.into();
    json!({
        "ok": false,
        "status": "failed",
        "summary": summary,
        "output": output.clone(),
        "artifacts": [],
        "warnings": [],
        "errors": [output],
        "data": data,
    })
}

pub(crate) fn skipped_output_result(
    summary: impl Into<String>,
    output: impl Into<String>,
    warnings: Vec<Value>,
    data: Value,
) -> Value {
    status_output_result("skipped", summary, output, warnings, data)
}

pub(crate) fn partial_output_result(
    summary: impl Into<String>,
    output: impl Into<String>,
    warnings: Vec<Value>,
    data: Value,
) -> Value {
    status_output_result("partial", summary, output, warnings, data)
}

fn status_output_result(
    status: &str,
    summary: impl Into<String>,
    output: impl Into<String>,
    warnings: Vec<Value>,
    data: Value,
) -> Value {
    json!({
        "ok": true,
        "status": status,
        "summary": summary.into(),
        "output": output.into(),
        "artifacts": [],
        "warnings": warnings,
        "errors": [],
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_result_uses_canonical_envelope_fields() {
        let result = completed_output_result("done", "done\n", json!({"count": 1}));

        assert_eq!(result["ok"], true);
        assert_eq!(result["status"], "completed");
        assert_eq!(result["summary"], "done");
        assert_eq!(result["output"], "done\n");
        assert_eq!(result["data"]["count"], 1);
        assert!(result["artifacts"].as_array().unwrap().is_empty());
        assert!(result["warnings"].as_array().unwrap().is_empty());
        assert!(result["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn failed_result_copies_output_into_errors() {
        let result = failed_output_result("missing tool", "scanner missing", json!({}));

        assert_eq!(result["ok"], false);
        assert_eq!(result["status"], "failed");
        assert_eq!(result["summary"], "missing tool");
        assert_eq!(result["errors"], json!(["scanner missing"]));
    }

    #[test]
    fn skipped_and_partial_results_preserve_warning_arrays() {
        let warnings = vec![json!("model not configured")];
        let skipped = skipped_output_result("skipped", "skipped", warnings.clone(), json!({}));
        let partial = partial_output_result("partial", "partial", warnings, json!({}));

        assert_eq!(skipped["ok"], true);
        assert_eq!(skipped["status"], "skipped");
        assert_eq!(skipped["warnings"], json!(["model not configured"]));
        assert_eq!(partial["ok"], true);
        assert_eq!(partial["status"], "partial");
        assert_eq!(partial["warnings"], json!(["model not configured"]));
    }
}
