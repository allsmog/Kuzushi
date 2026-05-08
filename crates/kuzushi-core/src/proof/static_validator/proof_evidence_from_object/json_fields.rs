use super::*;

pub(in crate::proof::static_validator) fn read_nested_object_string(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<String> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_string(nested, keys))
}

pub(in crate::proof::static_validator) fn read_object_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(in crate::proof::static_validator) fn read_object_u64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<u64> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
        })
    })
}

pub(in crate::proof::static_validator) fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(in crate::proof::static_validator) fn nonempty_option(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

pub(in crate::proof::static_validator) fn has_nonempty(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

pub(in crate::proof::static_validator) fn normalize_snippet(value: &str) -> String {
    value.replace("\r\n", "\n").trim_end().to_string()
}
