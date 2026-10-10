use crate::runtime::{RuntimeCost, RuntimeCostReport};
use anyhow::{Context, Result};
use serde_json::Value;

/// Parse the canonical cost claim mirrored at the tool-result envelope and
/// `data` levels.
///
/// Exact and unresolved-observed cost are mutually exclusive. Mirrored fields
/// must agree, malformed or invalid money is rejected, and an output with no
/// cost claim is `UNAVAILABLE` rather than an inferred zero.
pub fn tool_run_output_cost_report(output: &Value) -> Result<RuntimeCostReport> {
    validate_data_cost_scope(output)?;
    let exact = mirrored_cost(output, "costUsd")?;
    let observed = mirrored_cost(output, "observedCostUsd")?;
    let unresolved = mirrored_bool(output, "providerSpendUnresolved")?.unwrap_or(false);

    anyhow::ensure!(
        exact.is_none() || observed.is_none(),
        "tool result cannot claim both costUsd and observedCostUsd"
    );
    anyhow::ensure!(
        !unresolved || observed.is_some(),
        "tool result providerSpendUnresolved=true requires observedCostUsd"
    );
    anyhow::ensure!(
        observed.is_none() || unresolved,
        "tool result observedCostUsd requires providerSpendUnresolved=true"
    );

    Ok(match (exact, observed) {
        (Some(cost), None) => RuntimeCostReport::known(cost),
        (None, Some(cost)) => RuntimeCostReport::incomplete(cost),
        (None, None) => RuntimeCostReport::UNAVAILABLE,
        (Some(_), Some(_)) => unreachable!("contradictory cost fields rejected above"),
    })
}

fn validate_data_cost_scope(output: &Value) -> Result<()> {
    if let Some(scope) = output.get("dataCostScope") {
        anyhow::ensure!(
            scope == "projection",
            "Unsupported tool-result dataCostScope"
        );
    }
    Ok(())
}

fn mirrored_cost(output: &Value, key: &str) -> Result<Option<RuntimeCost>> {
    let mut cost = None;
    for (location, value) in mirrored_values(output, key) {
        let value = value
            .as_f64()
            .with_context(|| format!("tool result {location}.{key} must be a JSON number"))?;
        let value = RuntimeCost::from_usd(value, &format!("tool result {location}.{key}"))?;
        if let Some(existing) = cost {
            anyhow::ensure!(
                existing == value,
                "tool result has conflicting {key} values at envelope and data levels"
            );
        }
        cost = Some(value);
    }
    Ok(cost)
}

fn mirrored_bool(output: &Value, key: &str) -> Result<Option<bool>> {
    let mut parsed = None;
    for (location, value) in mirrored_values(output, key) {
        let value = value
            .as_bool()
            .with_context(|| format!("tool result {location}.{key} must be a boolean"))?;
        if let Some(existing) = parsed {
            anyhow::ensure!(
                existing == value,
                "tool result has conflicting {key} values at envelope and data levels"
            );
        }
        parsed = Some(value);
    }
    Ok(parsed)
}

fn mirrored_values<'a>(output: &'a Value, key: &str) -> Vec<(&'static str, &'a Value)> {
    let mut values = Vec::with_capacity(2);
    if let Some(value) = output.get(key).filter(|value| !value.is_null()) {
        values.push(("envelope", value));
    }
    if let Some(value) = output
        .get("data")
        .filter(|_| output.get("dataCostScope").and_then(Value::as_str) != Some("projection"))
        .and_then(Value::as_object)
        .and_then(|data| data.get(key))
        .filter(|value| !value.is_null())
    {
        values.push(("data", value));
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn historical_projection_never_becomes_current_execution_spend() {
        let data = json!({"totalCostUsd":1.0,"providerSpendUnresolved":true});
        assert!(tool_run_output_cost_report(&json!({"data":data})).is_err());
        let mut output = json!({"data":data,"dataCostScope":"projection"});
        assert!(tool_run_output_cost_report(&output)
            .unwrap()
            .is_unavailable());
        output["costUsd"] = json!(0.25);
        assert_eq!(
            tool_run_output_cost_report(&output).unwrap().exact_usd(),
            Some(0.25)
        );
        output["dataCostScope"] = json!(true);
        assert!(tool_run_output_cost_report(&output).is_err());
    }

    #[test]
    fn parses_exact_incomplete_and_unavailable_states() {
        let exact = tool_run_output_cost_report(&json!({
            "costUsd": 0.25,
            "data": {"costUsd": 0.25}
        }))
        .unwrap();
        let incomplete = tool_run_output_cost_report(&json!({
            "observedCostUsd": 0.1,
            "providerSpendUnresolved": true,
            "data": {
                "observedCostUsd": 0.1,
                "providerSpendUnresolved": true
            }
        }))
        .unwrap();
        let unavailable = tool_run_output_cost_report(&json!({"data": {}})).unwrap();

        assert_eq!(exact.exact_usd(), Some(0.25));
        assert_eq!(incomplete.observed_usd_if_available(), Some(0.1));
        assert!(!incomplete.is_complete());
        assert!(!incomplete.is_unavailable());
        assert!(unavailable.is_unavailable());
    }

    #[test]
    fn rejects_invalid_types_values_and_contradictory_states() {
        for invalid in [
            json!({"costUsd": "0.1"}),
            json!({"costUsd": -0.1}),
            json!({"costUsd": 0.1, "observedCostUsd": 0.1, "providerSpendUnresolved": true}),
            json!({"observedCostUsd": 0.1}),
            json!({"providerSpendUnresolved": true}),
            json!({"costUsd": 0.1, "data": {"costUsd": 0.2}}),
            json!({"providerSpendUnresolved": false, "data": {"providerSpendUnresolved": true}}),
        ] {
            assert!(tool_run_output_cost_report(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn null_optional_fields_are_absent_but_nested_types_are_still_checked() {
        assert!(tool_run_output_cost_report(&json!({
            "costUsd": null,
            "data": {"costUsd": null}
        }))
        .unwrap()
        .is_unavailable());
        assert!(tool_run_output_cost_report(&json!({
            "costUsd": 0.1,
            "data": {"costUsd": "bad"}
        }))
        .is_err());
    }
}
