//! Consensus over N independent adversarial verifier passes.
//!
//! Anthropic's defending-code harness reports that when a single
//! verification pass still lets unexploitable findings through, running
//! several independent verifiers and voting cuts the residual false
//! positives further. This module combines the normalized results of N
//! passes into one verdict, with a tie-breaking rule that matches the
//! adversarial default: a finding is confirmed exploitable only when a
//! *strict majority* of passes say so — ties and splits resolve to
//! not-exploitable.

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

/// Combine independent verifier-pass results into a single result object.
///
/// A single pass is returned unchanged (no consensus block) so the
/// common path is identical to single-pass verification. With more than
/// one pass, the representative result is the highest-confidence pass on
/// the winning side, its `confidence` replaced by the mean confidence of
/// the winning side, plus a `consensus` block recording the vote split
/// so the operator can see disagreement.
pub(in crate::verification::adapters) fn combine_verify_passes(passes: Vec<Value>) -> Result<Value> {
    anyhow::ensure!(
        !passes.is_empty(),
        "verification consensus requires at least one pass"
    );
    if passes.len() == 1 {
        let pass = passes
            .into_iter()
            .next()
            .context("verification consensus requires at least one pass")?;
        validate_consensus_pass(&pass)?;
        return Ok(pass);
    }

    let total = passes.len();
    for pass in &passes {
        validate_consensus_pass(pass)?;
    }
    let exploitable_votes = passes.iter().filter(|pass| is_exploitable(pass)).count();
    // Strict majority required to confirm exploitable — a tie is treated
    // as not-exploitable, consistent with "assume false positive".
    let exploitable = exploitable_votes * 2 > total;

    let winning: Vec<&Value> = passes
        .iter()
        .filter(|pass| is_exploitable(pass) == exploitable)
        .collect();
    let mut result = representative_pass(&winning).clone();
    overwrite(&mut result, "exploitable", json!(exploitable));
    overwrite(&mut result, "confidence", json!(mean_confidence(&winning)));
    overwrite(
        &mut result,
        "consensus",
        consensus_block(total, exploitable_votes, exploitable),
    );
    Ok(result)
}

fn consensus_block(total: usize, exploitable_votes: usize, exploitable: bool) -> Value {
    json!({
        "passes": total,
        "exploitableVotes": exploitable_votes,
        "notExploitableVotes": total - exploitable_votes,
        "verdict": if exploitable { "exploitable" } else { "not-exploitable" },
        "unanimous": exploitable_votes == 0 || exploitable_votes == total,
    })
}

fn is_exploitable(pass: &Value) -> bool {
    pass.get("exploitable")
        .and_then(Value::as_bool)
        .expect("validate_consensus_pass requires boolean exploitable")
}

fn confidence_of(pass: &Value) -> f64 {
    pass.get("confidence")
        .and_then(Value::as_f64)
        .expect("validate_consensus_pass requires numeric confidence")
}

fn validate_consensus_pass(pass: &Value) -> Result<()> {
    let Some(object) = pass.as_object() else {
        anyhow::bail!("verification consensus pass must be an object");
    };
    require_consensus_bool(object, "exploitable")?;
    require_consensus_number(object, "confidence")?;
    Ok(())
}

fn require_consensus_bool(object: &Map<String, Value>, key: &str) -> Result<()> {
    let value = object
        .get(key)
        .with_context(|| format!("verification consensus pass missing boolean `{key}`"))?;
    anyhow::ensure!(
        value.is_boolean(),
        "verification consensus pass field `{key}` must be boolean"
    );
    Ok(())
}

fn require_consensus_number(object: &Map<String, Value>, key: &str) -> Result<()> {
    let value = object
        .get(key)
        .with_context(|| format!("verification consensus pass missing number `{key}`"))?;
    anyhow::ensure!(
        value.is_number(),
        "verification consensus pass field `{key}` must be number"
    );
    Ok(())
}

/// The most confident pass on the winning side carries the reported PoC,
/// attack vector, and evidence.
fn representative_pass<'a>(winning: &[&'a Value]) -> &'a Value {
    winning
        .iter()
        .copied()
        .max_by(|a, b| {
            confidence_of(a)
                .partial_cmp(&confidence_of(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .expect("winning side is non-empty: every pass matches one verdict")
}

fn mean_confidence(passes: &[&Value]) -> f64 {
    if passes.is_empty() {
        return 0.0;
    }
    let sum: f64 = passes.iter().map(|pass| confidence_of(pass)).sum();
    (sum / passes.len() as f64).clamp(0.0, 1.0)
}

fn overwrite(result: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = result {
        object.insert(key.to_string(), value);
    } else {
        let mut object = Map::new();
        object.insert(key.to_string(), value);
        *result = Value::Object(object);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(exploitable: bool, confidence: f64) -> Value {
        json!({
            "fingerprint": "fp-1",
            "exploitable": exploitable,
            "confidence": confidence,
            "attackVector": if exploitable { json!("sqli") } else { json!(null) },
        })
    }

    #[test]
    fn single_pass_is_returned_unchanged() {
        let only = pass(true, 0.8);
        let combined = combine_verify_passes(vec![only.clone()]).unwrap();
        assert_eq!(combined, only);
        assert!(combined.get("consensus").is_none());
    }

    #[test]
    fn strict_majority_confirms_exploitable() {
        let combined = combine_verify_passes(vec![
            pass(true, 0.9),
            pass(true, 0.6),
            pass(false, 0.5),
        ])
        .unwrap();
        assert_eq!(combined["exploitable"], json!(true));
        // Mean over the two winning (exploitable) passes.
        assert_eq!(combined["confidence"], json!(0.75));
        assert_eq!(combined["consensus"]["exploitableVotes"], json!(2));
        assert_eq!(combined["consensus"]["notExploitableVotes"], json!(1));
        assert_eq!(combined["consensus"]["unanimous"], json!(false));
        // Representative is the most-confident exploitable pass.
        assert_eq!(combined["attackVector"], json!("sqli"));
    }

    #[test]
    fn tie_resolves_to_not_exploitable() {
        let combined = combine_verify_passes(vec![pass(true, 0.95), pass(false, 0.4)]).unwrap();
        assert_eq!(combined["exploitable"], json!(false));
        // Confidence is from the winning (not-exploitable) side only.
        assert_eq!(combined["confidence"], json!(0.4));
        assert_eq!(combined["consensus"]["verdict"], json!("not-exploitable"));
    }

    #[test]
    fn unanimous_not_exploitable_is_flagged() {
        let combined = combine_verify_passes(vec![pass(false, 0.3), pass(false, 0.5)]).unwrap();
        assert_eq!(combined["exploitable"], json!(false));
        assert_eq!(combined["consensus"]["unanimous"], json!(true));
        assert_eq!(combined["consensus"]["exploitableVotes"], json!(0));
    }

    #[test]
    fn malformed_pass_errors_instead_of_defaulting_to_not_exploitable() {
        let error = combine_verify_passes(vec![json!({
            "fingerprint": "fp-1",
            "confidence": 0.5
        })])
        .unwrap_err()
        .to_string();

        assert!(error.contains("missing boolean `exploitable`"));
    }
}
