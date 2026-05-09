use super::*;

pub(in crate::scan) fn optional_string_any(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .and_then(non_empty_string)
            .map(ToString::to_string)
    })
}

pub(in crate::scan) fn positive_u32(input: &Value, key: &str) -> Result<Option<u32>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    };
    match parsed {
        Some(value) if value >= 1 => Ok(Some(value.min(u32::MAX as u64) as u32)),
        _ => anyhow::bail!("codeql: {key} must be a positive integer"),
    }
}

pub(in crate::scan) fn non_empty_string(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub(in crate::scan) fn shell_join(args: &[String]) -> String {
    args.join(" ")
}
