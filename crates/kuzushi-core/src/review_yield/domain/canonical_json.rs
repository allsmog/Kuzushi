use anyhow::Result;
use serde::Serialize;
use serde_json::{Map, Value};

/// Serializes a value to canonical JSON bytes: compact, with object keys
/// sorted at every depth.
///
/// The digest and the written file must agree byte for byte, and neither may
/// depend on whether `serde_json` was built with `preserve_order`, so key order
/// is imposed here rather than inherited from the map type.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    Ok(canonicalize(&value).to_string().into_bytes())
}

/// Canonical bytes of a JSON object with one top-level key removed. Used for
/// the manifest digest, which cannot cover the digest field itself.
pub fn canonical_json_bytes_without_key<T: Serialize>(value: &T, key: &str) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    if let Some(object) = value.as_object_mut() {
        object.remove(key);
    }
    Ok(canonicalize(&value).to_string().into_bytes())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(entries) => Value::Object(sorted_object(entries)),
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn sorted_object(entries: &Map<String, Value>) -> Map<String, Value> {
    let mut keys: Vec<&String> = entries.keys().collect();
    keys.sort();
    keys.into_iter()
        .filter_map(|key| entries.get(key).map(|value| (key.clone(), canonicalize(value))))
        .collect()
}
