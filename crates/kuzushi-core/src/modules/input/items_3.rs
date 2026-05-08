use super::prelude::*;
use super::*;

pub(in crate::modules) fn string_input_any(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(in crate::modules) fn string_array_or_csv_input(
    input: &Value,
    keys: &[&str],
) -> Option<Vec<String>> {
    keys.iter().find_map(|key| match input.get(*key) {
        Some(Value::String(value)) => Some(
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        _ => None,
    })
}

pub(in crate::modules) fn read_bool_any(input: &Value, keys: &[&str]) -> Result<Option<bool>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .map(Some)
                .with_context(|| format!("{key} must be a boolean"));
        }
    }
    Ok(None)
}

pub(in crate::modules) fn resolve_input_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}
