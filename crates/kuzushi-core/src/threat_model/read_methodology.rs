use super::*;

pub(crate) fn read_methodology(input: &Value, fallback: &str) -> String {
    read_string(input, &["methodology", "type"])
        .map(|value| value.to_lowercase())
        .filter(|value| VALID_METHODOLOGIES.contains(&value.as_str()))
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn read_string(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(crate) fn read_bool(input: &Value, keys: &[&str], fallback: bool) -> bool {
    keys.iter()
        .find_map(|key| input.get(*key).and_then(Value::as_bool))
        .unwrap_or(fallback)
}

pub(crate) fn read_usize(input: &Value, keys: &[&str], fallback: usize, min: usize) -> usize {
    let value = keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .or_else(|| {
                input
                    .get(*key)
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<usize>().ok())
            })
    });
    value.filter(|value| *value >= min).unwrap_or(fallback)
}

pub(crate) fn repo_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("repo")
        .to_string()
}
