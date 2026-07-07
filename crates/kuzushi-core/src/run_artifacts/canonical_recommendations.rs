use serde_json::Value;

const LEGACY_RECOMMENDATION_POINTERS: &[&str] = &["/data/recommendations", "/recommendations"];

pub(crate) fn recommendations_snapshot_value(output: &Value) -> Option<&Value> {
    full_recommendation_report_value(output)
        .or_else(|| value_at(output, LEGACY_RECOMMENDATION_POINTERS))
}

fn full_recommendation_report_value(output: &Value) -> Option<&Value> {
    full_recommendation_report_at(output, "")
        .or_else(|| full_recommendation_report_at(output, "/data"))
        .or_else(|| full_recommendation_report_at(output, "/recommendationReport"))
        .or_else(|| full_recommendation_report_at(output, "/data/recommendationReport"))
}

fn full_recommendation_report_at<'a>(output: &'a Value, pointer: &str) -> Option<&'a Value> {
    let value = if pointer.is_empty() {
        output
    } else {
        output.pointer(pointer)?
    };
    is_recommendation_report(value).then_some(value)
}

fn is_recommendation_report(value: &Value) -> bool {
    value
        .get("recommendations")
        .and_then(Value::as_array)
        .is_some()
        && value.get("summary").and_then(Value::as_str).is_some()
        && value.get("signals").and_then(Value::as_object).is_some()
        && available_tool_count(value).is_some()
}

fn available_tool_count(value: &Value) -> Option<u64> {
    value
        .pointer("/capabilities/availableToolCount")
        .or_else(|| value.pointer("/capabilities/available_tool_count"))
        .and_then(Value::as_u64)
}

fn value_at<'a>(output: &'a Value, pointers: &[&str]) -> Option<&'a Value> {
    pointers
        .iter()
        .filter_map(|pointer| output.pointer(pointer))
        .find(|value| !value.is_null())
}
