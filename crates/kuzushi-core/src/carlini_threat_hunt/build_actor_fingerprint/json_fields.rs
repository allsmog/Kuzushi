use super::*;

pub(in crate::carlini_threat_hunt) fn object_string_value(
    value: &Value,
    keys: &[&str],
) -> Option<String> {
    let object = value.as_object()?;
    read_object_string(object, keys)
}

pub(in crate::carlini_threat_hunt) fn object_string_array(
    value: &Value,
    keys: &[&str],
) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    read_object_string_array(object, keys)
}

pub(in crate::carlini_threat_hunt) fn read_object_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(in crate::carlini_threat_hunt) fn read_object_u64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_u64)
}

pub(in crate::carlini_threat_hunt) fn read_object_string_array(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Vec<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
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

pub(in crate::carlini_threat_hunt) fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if !value.trim().is_empty() && seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}
