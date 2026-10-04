//! A model's conclusion is decisive only when its cited source can be checked.
use crate::proof::static_validator::{verify_static_proof_citation, StaticProofCitation};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn enforce_citations(root: &Path, raw: &Value, result: &mut Value) {
    let conclusion = result["exploitable"].as_bool();
    result["confidenceKind"] = json!("uncalibrated-model-assessment");
    result["rawModelConfidence"] = result["confidence"].clone();
    let Some(conclusion) = conclusion else {
        return;
    };
    match check_citations(root, raw, result, conclusion) {
        Ok(citations) => {
            result["citationValidation"] = json!({"status":"verified", "citations":citations})
        }
        Err(error) => degrade(result, &error.to_string()),
    }
}

fn check_citations(
    root: &Path,
    raw: &Value,
    result: &Value,
    conclusion: bool,
) -> Result<Vec<Value>> {
    let input = raw
        .get("codeCitations")
        .or_else(|| raw.get("code_citations"))
        .and_then(Value::as_array)
        .context("source citations are required")?;
    let normalized = result["codeCitations"]
        .as_array()
        .context("source citations are malformed")?;
    anyhow::ensure!(
        !input.is_empty() && input.len() <= 64,
        "expected 1..=64 source citations"
    );
    anyhow::ensure!(
        input.len() == normalized.len(),
        "one or more source citations are malformed"
    );
    let verified = normalized
        .iter()
        .map(|citation| validate_one(root, citation))
        .collect::<Result<Vec<_>>>()?;
    require_roles(normalized, conclusion)?;
    Ok(verified)
}

fn validate_one(root: &Path, value: &Value) -> Result<Value> {
    let citation: StaticProofCitation =
        serde_json::from_value(value.clone()).context("invalid source citation")?;
    anyhow::ensure!(
        citation
            .snippet
            .as_deref()
            .is_some_and(|text| !text.trim().is_empty()),
        "source citations require the exact cited snippet"
    );
    anyhow::ensure!(
        citation.end_line >= citation.start_line && citation.end_line - citation.start_line < 200,
        "source citation range must contain 1..=200 lines"
    );
    let verified = verify_static_proof_citation(root, &citation)?;
    // extract_source_span may clip a requested range; clipping is not verification.
    anyhow::ensure!(
        verified.end_line == citation.end_line,
        "source citation extends past the file"
    );
    Ok(serde_json::to_value(verified)?)
}

fn require_roles(citations: &[Value], conclusion: bool) -> Result<()> {
    let roles: Vec<_> = citations
        .iter()
        .filter_map(|value| value["role"].as_str())
        .collect();
    if conclusion {
        anyhow::ensure!(
            roles.contains(&"source") && roles.contains(&"sink"),
            "positive assessments require cited source and sink evidence"
        );
    } else {
        anyhow::ensure!(
            roles.contains(&"control") || roles.contains(&"reachability"),
            "negative assessments require a cited defeating control or reachability reason"
        );
    }
    Ok(())
}

fn degrade(result: &mut Value, reason: &str) {
    result["modelClaimedExploitable"] = result["exploitable"].clone();
    result["exploitable"] = Value::Null;
    result["proofVerdict"] = json!("inconclusive");
    result["proofLevel"] = json!(1);
    result["pocPayload"] = Value::Null;
    result["citationValidation"] = json!({"status":"unverified", "reason":reason});
}

#[cfg(test)]
mod tests {
    use super::super::verify_finding_result::normalize_verification_result;
    use super::*;

    fn review(root: &Path, citations: Value, positive: bool) -> Value {
        let raw = json!({"exploitable":positive,"confidence":0.99,"codeCitations":citations});
        let mut result = normalize_verification_result(raw.clone(), "fp").unwrap();
        enforce_citations(root, &raw, &mut result);
        result
    }

    fn citation(role: &str) -> Value {
        json!({"filePath":"app.rs","startLine":1,"endLine":1,"snippet":"sink(input);",
            "role":role,"description":"the cited security operation"})
    }

    #[test]
    fn unsupported_model_claims_remain_inconclusive() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "sink(input);\n").unwrap();
        let mut outside = citation("control");
        outside["startLine"] = json!(999);
        outside["endLine"] = json!(999);
        let mut mismatch = citation("control");
        mismatch["snippet"] = json!("imaginary_guard();");
        for citations in [
            Value::Null,
            json!([]),
            json!([{}]),
            json!([outside]),
            json!([mismatch]),
            json!([citation("control"), {}]),
            json!([citation("source")]),
        ] {
            for positive in [false, true] {
                assert!(review(root.path(), citations.clone(), positive)["exploitable"].is_null());
            }
        }
        assert_eq!(
            review(
                root.path(),
                json!([citation("source"), citation("sink")]),
                true
            )["exploitable"],
            true
        );
        assert_eq!(
            review(root.path(), json!([citation("control")]), false)["exploitable"],
            false
        );
    }
}
