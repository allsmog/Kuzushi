//! Pure bounds for operator-requested actor work and query settings.
use super::*;

pub(super) fn bounded_integer(
    input: &Value,
    keys: &[&str],
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<usize> {
    let Some((key, value)) = keys
        .iter()
        .find_map(|key| input.get(*key).map(|value| (*key, value)))
    else {
        return Ok(default as usize);
    };
    let number = match value {
        Value::String(text) => text.trim().parse().ok(),
        _ => value.as_u64(),
    }
    .with_context(|| format!("Actor discovery {key} must be a positive integer"))?;
    anyhow::ensure!(
        range.contains(&number),
        "Actor discovery {key} must be between {} and {}",
        range.start(),
        range.end()
    );
    usize::try_from(number).context("Actor discovery limit does not fit this platform")
}

pub(super) fn actor_reasoning(input: &Value) -> Result<Option<String>> {
    let selected = optional_string(
        input,
        &[
            "thinkingLevel",
            "thinking_level",
            "reasoningEffort",
            "effort",
        ],
    )?;
    if let Some(level) = &selected {
        anyhow::ensure!(
            matches!(
                level.as_str(),
                "minimal" | "low" | "medium" | "high" | "xhigh"
            ),
            "Actor discovery thinkingLevel is unsupported"
        );
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_reasoning_inherits_and_invalid_values_do_not_silently_change_it() {
        assert_eq!(actor_reasoning(&json!({})).unwrap(), None);
        assert_eq!(
            actor_reasoning(&json!({"thinkingLevel":"medium"})).unwrap(),
            Some("medium".into())
        );
        assert_eq!(
            actor_reasoning(&json!({"reasoningEffort":"low"})).unwrap(),
            Some("low".into())
        );
        assert!(actor_reasoning(&json!({"thinkingLevel":"expensive"})).is_err());
    }
    #[test]
    fn declared_bounds_also_protect_the_direct_capability_path() {
        for value in [json!(0), json!(9), json!(-1), json!("wrong")] {
            assert!(
                bounded_integer(&json!({"maxActors":value}), &["maxActors"], 5, 1..=8).is_err()
            );
        }
        assert_eq!(
            bounded_integer(&json!({"maxActors":"2"}), &["maxActors"], 5, 1..=8).unwrap(),
            2
        );
    }
}
