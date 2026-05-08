use super::prelude::*;
use super::*;

pub(in crate::modules) fn render_report_markdown(report: &Value) -> String {
    let mut lines = vec![
        "# Vendor AI Security Assessment Report".to_string(),
        String::new(),
        format!(
            "Overall risk: {}",
            report
                .get("overallRisk")
                .and_then(Value::as_str)
                .unwrap_or("needs-review")
        ),
        format!(
            "Confidence: {}",
            report
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or("low")
        ),
        String::new(),
        report
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("No summary supplied.")
            .to_string(),
        String::new(),
        "## Appendix".to_string(),
        format!(
            "Documents: {}",
            report
                .get("documents")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        ),
    ];
    if let Some(items) = report.get("mitigations").and_then(Value::as_array) {
        lines.push(String::new());
        lines.push("## Mitigations".to_string());
        for item in items {
            lines.push(format!("- {}", json_summary(item)));
        }
    }
    lines.join("\n")
}
