//! Consensus retains incomplete evidence and disagreement as inconclusive.

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
pub(in crate::verification::adapters) fn combine_verify_passes(
    passes: Vec<Value>,
) -> Result<Value> {
    anyhow::ensure!(
        !passes.is_empty(),
        "verification consensus requires at least one pass"
    );
    for pass in &passes {
        validate_consensus_pass(pass)?;
    }
    if passes.len() == 1 {
        return passes
            .into_iter()
            .next()
            .context("verification pass is missing");
    }
    combine_panel(&passes)
}

fn combine_panel(passes: &[Value]) -> Result<Value> {
    let positive = vote_count(passes, Some(true));
    let negative = vote_count(passes, Some(false));
    let verdict = majority_verdict(passes.len(), positive, negative);
    let winning = representative_pool(passes, verdict);
    let mut result = representative_pass(&winning).clone();
    overwrite(&mut result, "exploitable", json!(verdict));
    overwrite(&mut result, "confidence", json!(mean_confidence(&winning)));
    overwrite(
        &mut result,
        "confidenceKind",
        json!("uncalibrated-model-assessment"),
    );
    overwrite(
        &mut result,
        "consensus",
        consensus_block(passes.len(), positive, negative, verdict),
    );
    result["consensus"]["assessments"] = json!(passes);
    if verdict.is_none() {
        overwrite(&mut result, "proofVerdict", json!("inconclusive"));
        overwrite(&mut result, "pocPayload", Value::Null);
    }
    Ok(result)
}

fn vote_count(passes: &[Value], verdict: Option<bool>) -> usize {
    passes
        .iter()
        .filter(|pass| exploitability_of(pass) == verdict)
        .count()
}

fn majority_verdict(total: usize, positive: usize, negative: usize) -> Option<bool> {
    if positive * 2 > total {
        return Some(true);
    }
    (negative * 2 > total).then_some(false)
}

fn representative_pool(passes: &[Value], verdict: Option<bool>) -> Vec<&Value> {
    let matching: Vec<_> = passes
        .iter()
        .filter(|pass| exploitability_of(pass) == verdict)
        .collect();
    if matching.is_empty() {
        return passes.iter().collect();
    }
    matching
}

/// True when the panel's vote was an even split (equal exploitable and
/// not-exploitable votes with no inconclusive votes). A split stays inconclusive
/// unless an explicitly configured, different-model tie-break resolves it. A single pass has no consensus block and is
/// never a split.
pub(in crate::verification::adapters) fn panel_verdict_is_split(result: &Value) -> bool {
    let Some(consensus) = result.get("consensus") else {
        return false;
    };
    let passes = consensus.get("passes").and_then(Value::as_u64);
    let exploitable_votes = consensus.get("exploitableVotes").and_then(Value::as_u64);
    let incomplete = consensus
        .get("inconclusiveVotes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    match (passes, exploitable_votes) {
        (Some(passes), Some(votes)) => passes > 1 && incomplete == 0 && votes * 2 == passes,
        _ => false,
    }
}

fn consensus_block(total: usize, positive: usize, negative: usize, verdict: Option<bool>) -> Value {
    json!({
        "passes": total,
        "exploitableVotes": positive,
        "notExploitableVotes": negative,
        "inconclusiveVotes": total - positive - negative,
        "verdict": match verdict {
            Some(true) => "exploitable",
            Some(false) => "not-exploitable",
            None => "inconclusive",
        },
        "unanimous": positive == total || negative == total,
    })
}

fn exploitability_of(pass: &Value) -> Option<bool> {
    super::verify_assessment::read_exploitability(pass)
        .expect("validate_consensus_pass requires boolean or null exploitable")
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
    super::verify_assessment::read_exploitability(pass)?;
    require_consensus_number(object, "confidence")?;
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
    fn incomplete_votes_do_not_count_as_negative_votes() {
        let unknown = json!({"exploitable":null,"confidence":0.2,"proofVerdict":"insufficient_finding_detail"});
        let result = combine_verify_passes(vec![pass(false, 0.8), unknown.clone()]).unwrap();
        assert!(result["exploitable"].is_null());
        assert_eq!(result["consensus"]["notExploitableVotes"], 1);
        assert_eq!(result["consensus"]["inconclusiveVotes"], 1);
        assert!(!panel_verdict_is_split(&result));
        let majority =
            combine_verify_passes(vec![pass(false, 0.8), pass(false, 0.7), unknown]).unwrap();
        assert_eq!(majority["exploitable"], false);
        assert_eq!(majority["consensus"]["unanimous"], false);
    }

    #[test]
    fn an_entirely_incomplete_panel_stays_inconclusive() {
        let unknown = json!({"exploitable":null,"confidence":0.2});
        let result = combine_verify_passes(vec![unknown.clone(), unknown]).unwrap();
        assert!(result["exploitable"].is_null());
        assert_eq!(result["consensus"]["inconclusiveVotes"], 2);
        assert_eq!(result["consensus"]["unanimous"], false);
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
        let combined =
            combine_verify_passes(vec![pass(true, 0.9), pass(true, 0.6), pass(false, 0.5)])
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
    fn dissenting_evidence_survives_either_pass_order() {
        let mut dissent = pass(false, 0.8);
        dissent["codeCitations"] = json!([{"description":"authentication guard"}]);
        let mut votes = vec![pass(true, 0.9), pass(true, 0.7), dissent.clone()];
        for _ in 0..2 {
            let result = combine_verify_passes(votes.clone()).unwrap();
            assert!(result["consensus"]["assessments"]
                .as_array()
                .unwrap()
                .contains(&dissent));
            votes.reverse();
        }
    }

    #[test]
    fn tie_stays_inconclusive() {
        let combined = combine_verify_passes(vec![pass(true, 0.95), pass(false, 0.4)]).unwrap();
        assert!(combined["exploitable"].is_null());
        assert_eq!(combined["proofVerdict"], "inconclusive");
        assert_eq!(combined["consensus"]["verdict"], "inconclusive");
    }

    #[test]
    fn unanimous_not_exploitable_is_flagged() {
        let combined = combine_verify_passes(vec![pass(false, 0.3), pass(false, 0.5)]).unwrap();
        assert_eq!(combined["exploitable"], json!(false));
        assert_eq!(combined["consensus"]["unanimous"], json!(true));
        assert_eq!(combined["consensus"]["exploitableVotes"], json!(0));
    }

    #[test]
    fn panel_verdict_is_split_only_on_an_even_two_way_vote() {
        let even = combine_verify_passes(vec![pass(true, 0.9), pass(false, 0.4)]).unwrap();
        assert!(panel_verdict_is_split(&even));

        let majority =
            combine_verify_passes(vec![pass(true, 0.9), pass(true, 0.6), pass(false, 0.5)])
                .unwrap();
        assert!(!panel_verdict_is_split(&majority));

        let single = combine_verify_passes(vec![pass(true, 0.9)]).unwrap();
        assert!(!panel_verdict_is_split(&single));
    }

    #[test]
    fn malformed_pass_errors_instead_of_defaulting_to_not_exploitable() {
        let error = combine_verify_passes(vec![json!({
            "fingerprint": "fp-1",
            "confidence": 0.5
        })])
        .unwrap_err()
        .to_string();

        assert!(error.contains("missing boolean or null `exploitable`"));
    }
}
