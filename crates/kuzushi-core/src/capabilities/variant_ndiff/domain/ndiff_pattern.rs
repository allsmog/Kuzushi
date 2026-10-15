use super::*;

pub(crate) fn ndiff_pattern_schema() -> Value {
    let text = json!({"type":"string","minLength":1,"maxLength":4096});
    json!({"type":"object","required":["fixShape","vulnerableShape"],
        "properties":{"fixShape":text,"vulnerableShape":text},"additionalProperties":true})
}

pub(crate) fn validate_ndiff_pattern_output(value: Value) -> Result<Value> {
    let object = value
        .as_object()
        .context("Advisory-pattern output must be an object")?;
    validate_ndiff_pattern(object)?;
    Ok(value)
}

pub(crate) fn validate_ndiff_pattern(pattern: &Map<String, Value>) -> Result<()> {
    for keys in [
        ["fixShape", "fix_shape"],
        ["vulnerableShape", "vulnerable_shape"],
    ] {
        let text = read_object_value(pattern, &keys)
            .and_then(Value::as_str)
            .with_context(|| format!("Advisory pattern requires {} text", keys[0]))?;
        anyhow::ensure!(
            !text.trim().is_empty(),
            "Advisory pattern {} must not be blank",
            keys[0]
        );
        anyhow::ensure!(
            text.len() <= 4096,
            "Advisory pattern {} exceeds 4096 bytes",
            keys[0]
        );
    }
    Ok(())
}

pub(crate) fn ndiff_query_limit(
    input: &Value,
    key: &str,
    default: usize,
    range: std::ops::RangeInclusive<usize>,
) -> Result<usize> {
    let Some(value) = input.get(key) else {
        return Ok(default);
    };
    let number = ndiff_limit_integer(value)
        .with_context(|| format!("Advisory search {key} must be a positive integer"))?;
    anyhow::ensure!(
        range.contains(&number),
        "Advisory search {key} is out of range"
    );
    Ok(number)
}

fn ndiff_limit_integer(value: &Value) -> Option<usize> {
    match value {
        Value::Number(number) => usize::try_from(number.as_u64()?).ok(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_require_both_nonblank_bounded_shapes_and_keep_legacy_keys() {
        for value in [
            json!({}),
            json!({"fixShape":"ok","vulnerableShape":" "}),
            json!({"fixShape":"x".repeat(4097),"vulnerableShape":"ok"}),
        ] {
            assert!(validate_ndiff_pattern(value.as_object().unwrap()).is_err());
        }
        validate_ndiff_pattern(
            json!({"fix_shape":"owned changed marker","vulnerable_shape":"owned prior marker"})
                .as_object()
                .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn invalid_direct_limits_fail_instead_of_clamping_or_substituting_defaults() {
        for value in [
            json!(0),
            json!(101),
            json!(-1),
            json!(1.5),
            json!(true),
            json!("unknown"),
        ] {
            assert!(
                ndiff_query_limit(&json!({"maxFindings":value}), "maxFindings", 25, 1..=100)
                    .is_err()
            );
        }
        assert_eq!(
            ndiff_query_limit(&json!({"maxFindings":"3"}), "maxFindings", 25, 1..=100).unwrap(),
            3
        );
        assert_eq!(
            ndiff_query_limit(&json!({}), "maxFindings", 25, 1..=100).unwrap(),
            25
        );
    }
}
