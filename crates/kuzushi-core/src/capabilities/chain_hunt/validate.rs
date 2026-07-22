//! Honesty gate for model-proposed chains: members must resolve to real
//! confirmed findings, and a chain needs at least two distinct members.

use super::{Finding, HuntedChains, MemberRef, ModelChain};
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn validate_chain_hunt_output(
    value: Value,
    max_chains: usize,
    by_fingerprint: &BTreeMap<&str, &Finding>,
) -> Result<HuntedChains> {
    let Some(items) = value.get("chains").and_then(Value::as_array) else {
        anyhow::bail!("triage:chain-hunt output must contain a `chains` array");
    };
    let mut chains = Vec::new();
    let mut dropped = 0usize;
    for item in items {
        match validated_model_chain(item, by_fingerprint) {
            Some(chain) if chains.len() < max_chains => chains.push(chain),
            Some(_) => dropped += 1,
            None => dropped += 1,
        }
    }
    Ok(HuntedChains { chains, dropped })
}

/// Membership is the honesty gate: a chain survives only when at least two
/// distinct member fingerprints resolve to real confirmed findings.
fn validated_model_chain(
    item: &Value,
    by_fingerprint: &BTreeMap<&str, &Finding>,
) -> Option<ModelChain> {
    let members: Vec<MemberRef> = item
        .get("members")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|fingerprint| by_fingerprint.get(fingerprint.trim()))
        .map(|finding| member_ref(finding))
        .collect();
    let mut distinct = members
        .iter()
        .map(|member| member.fingerprint.clone())
        .collect::<Vec<_>>();
    distinct.sort();
    distinct.dedup();
    if distinct.len() < 2 {
        return None;
    }
    Some(ModelChain {
        title: nonempty_str(item, "title")?,
        members,
        attack_path: string_list(item, "attack_path"),
        cumulative_impact: nonempty_str(item, "cumulative_impact").unwrap_or_default(),
        why_this_chain_matters: nonempty_str(item, "why_this_chain_matters").unwrap_or_default(),
        detection_difficulty: nonempty_str(item, "detection_difficulty").unwrap_or_default(),
    })
}

fn member_ref(finding: &Finding) -> MemberRef {
    MemberRef {
        fingerprint: finding.fingerprint.clone(),
        title: finding.title.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        severity: finding.severity,
    }
}

fn nonempty_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_list(item: &Value, key: &str) -> Vec<String> {
    item.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use serde_json::json;

    fn confirmed(fingerprint: &str, title: &str, severity: Severity, path: &str) -> Finding {
        let mut finding = Finding::new_tool("agentic", "rule", path, 10, None, severity, title);
        finding.fingerprint = fingerprint.to_string();
        finding
    }

    #[test]
    fn hallucinated_members_drop_the_chain() {
        let a = confirmed("fp-a", "Entry", Severity::High, "svc/a.c");
        let by_fp: BTreeMap<&str, &Finding> = [("fp-a", &a)].into_iter().collect();
        let output = json!({"chains": [
            {"title": "Ghost chain", "members": ["fp-a", "fp-ghost"],
             "attack_path": ["step"], "cumulative_impact": "x"}
        ]});
        let hunted = validate_chain_hunt_output(output, 8, &by_fp).unwrap();
        assert!(hunted.chains.is_empty());
        assert_eq!(hunted.dropped, 1);
    }

    #[test]
    fn duplicate_member_fingerprints_do_not_count_as_two() {
        let a = confirmed("fp-a", "Entry", Severity::High, "svc/a.c");
        let by_fp: BTreeMap<&str, &Finding> = [("fp-a", &a)].into_iter().collect();
        let output = json!({"chains": [
            {"title": "Self chain", "members": ["fp-a", "fp-a"],
             "attack_path": [], "cumulative_impact": "none"}
        ]});
        let hunted = validate_chain_hunt_output(output, 8, &by_fp).unwrap();
        assert!(hunted.chains.is_empty());
    }
}
