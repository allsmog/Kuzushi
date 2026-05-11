use super::*;

pub(crate) fn lean_prompt_payload<T: Serialize>(value: &T) -> Result<String> {
    let mut json = serde_json::to_value(value)?;
    for field in [
        "surfacePacks",
        "surface_packs",
        "line_content",
        "lineContent",
        "snippet",
    ] {
        strip_field_recursively(&mut json, field);
    }
    serde_json::to_string_pretty(&json).map_err(Into::into)
}

fn strip_field_recursively(value: &mut Value, field: &str) {
    match value {
        Value::Object(map) => {
            map.remove(field);
            for value in map.values_mut() {
                strip_field_recursively(value, field);
            }
        }
        Value::Array(items) => {
            for value in items {
                strip_field_recursively(value, field);
            }
        }
        _ => {}
    }
}
