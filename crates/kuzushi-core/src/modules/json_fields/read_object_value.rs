use super::*;

pub(in crate::modules) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(in crate::modules) fn read_object_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(in crate::modules) fn read_object_nullable_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    read_object_value(object, keys).and_then(|value| match value {
        Value::String(text) => Some(text.to_string()),
        Value::Null => None,
        _ => None,
    })
}

pub(in crate::modules) fn read_object_bool(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<bool> {
    read_object_value(object, keys).and_then(Value::as_bool)
}

pub(in crate::modules) fn read_object_f64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<f64> {
    read_object_value(object, keys).and_then(Value::as_f64)
}

pub(in crate::modules) fn read_object_u64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

pub(in crate::modules) fn read_object_string_array(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Vec<String> {
    read_object_value(object, keys)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(in crate::modules) fn normalize_object_array(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<Value> {
    let items = read_object_string_array(object, keys);
    if items.is_empty() {
        None
    } else {
        Some(json!(items))
    }
}

pub(in crate::modules) fn string_or_null(value: Option<String>) -> Value {
    match value {
        Some(value) => json!(value),
        None => Value::Null,
    }
}
