use anyhow::{Context, Result};
use serde_json::{Map, Value};

pub(super) fn read_exploitability(result: &Value) -> Result<Option<bool>> {
    let value = result
        .get("exploitable")
        .context("verification output missing boolean or null `exploitable`")?;
    match value {
        Value::Null => Ok(None),
        Value::Bool(value) => Ok(Some(*value)),
        _ => anyhow::bail!("verification output `exploitable` must be boolean or null"),
    }
}

pub(super) fn normalize_exploitability(object: &Map<String, Value>) -> Result<Option<bool>> {
    let value = read_exploitability(&Value::Object(object.clone()))?;
    let verdict = super::json_fields::read_object_value(object, &["proofVerdict", "proof_verdict"]);
    match verdict {
        None => Ok(value),
        Some(Value::String(verdict)) => assessment_for_verdict(value, verdict),
        Some(_) => anyhow::bail!("verification output `proofVerdict` must be a string"),
    }
}

fn assessment_for_verdict(value: Option<bool>, verdict: &str) -> Result<Option<bool>> {
    match verdict.trim() {
        // Older responses used false for these explicitly incomplete outcomes.
        "insufficient_finding_detail" | "language_unsupported_yet" | "inconclusive" => Ok(None),
        "exploited" => require_assessment(value, true),
        "not_reproduced" => require_assessment(value, false),
        _ => anyhow::bail!("verification output contains an unsupported proof verdict"),
    }
}

fn require_assessment(value: Option<bool>, expected: bool) -> Result<Option<bool>> {
    anyhow::ensure!(
        value == Some(expected),
        "verification proof verdict contradicts exploitability"
    );
    Ok(value)
}

pub(super) fn assessment_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "likely-exploitable (model assessment)",
        Some(false) => "likely-not-exploitable (model assessment)",
        None => "inconclusive (model assessment)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incomplete_verdict_never_becomes_a_negative_assessment() {
        for verdict in ["insufficient_finding_detail", "language_unsupported_yet"] {
            for value in [json!(false), Value::Null, json!(true)] {
                let result = json!({"exploitable":value,"proofVerdict":verdict});
                assert_eq!(
                    normalize_exploitability(result.as_object().unwrap()).unwrap(),
                    None
                );
            }
        }
    }

    #[test]
    fn known_verdict_requires_a_matching_conclusion() {
        for (verdict, value) in [("exploited", true), ("not_reproduced", false)] {
            let mut result = json!({"exploitable":value,"proof_verdict":verdict});
            assert_eq!(
                normalize_exploitability(result.as_object().unwrap()).unwrap(),
                Some(value)
            );
            result["exploitable"] = json!(!value);
            assert!(normalize_exploitability(result.as_object().unwrap()).is_err());
            result["exploitable"] = Value::Null;
            assert!(normalize_exploitability(result.as_object().unwrap()).is_err());
        }
    }

    #[test]
    fn malformed_fields_are_rejected_without_echoing_content() {
        for result in [
            json!({}),
            json!({"exploitable":"private value"}),
            json!({"exploitable":false,"proofVerdict":"private value"}),
            json!({"exploitable":false,"proofVerdict":42}),
        ] {
            let error = normalize_exploitability(result.as_object().unwrap())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private value"));
        }
    }
}
