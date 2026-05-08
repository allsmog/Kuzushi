use super::*;

pub(crate) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

pub(crate) fn read_object_string_array(object: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
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

pub(crate) fn stable_fingerprint(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in parts {
        for byte in part.as_bytes().iter().chain(std::iter::once(&0)) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
}

pub(crate) fn repo_name(target: &Path) -> String {
    target
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("repo")
        .to_string()
}

pub(crate) fn shell_escape_url(value: &str) -> String {
    value.trim().replace(' ', "%20")
}

pub(crate) const WHITEBOX_SOURCE_TOKENS: &[&str] = &[
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "request.args",
    "request.form",
    "request.json",
    "process.argv",
    "argv",
    "urlsearchparams",
    "input",
];

pub(crate) const WHITEBOX_SINK_TOKENS: &[&str] = &[
    "db.query",
    ".query(",
    "execute(",
    "exec(",
    "spawn(",
    "eval(",
    "res.send",
    "innerhtml",
    "deserialize",
    "render(",
];

pub(crate) const WHITEBOX_GUARD_TOKENS: &[&str] = &[
    "sanitize",
    "sanitise",
    "escape",
    "validate",
    "validator",
    "allowlist",
    "allow_list",
    "parameterized",
    "parametrize",
    "prepare(",
    "preparedstatement",
    "dompurify",
    "zod",
    "joi",
];
