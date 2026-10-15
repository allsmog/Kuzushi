use super::*;

pub(super) fn with_inspection_receipts(mut result: Value, receipts: Vec<Value>) -> Value {
    if let Some(data) = result.get_mut("data").and_then(Value::as_object_mut) {
        data.insert("nativeInspections".into(), json!(receipts));
    }
    if let Some(output) = result.get("output").and_then(Value::as_str) {
        let mut lines = vec![output.to_string()];
        crate::modules::application::sast_scan::append_inspection_lines(&receipts, &mut lines);
        result["output"] = json!(lines.join("\n"));
    }
    result
}
