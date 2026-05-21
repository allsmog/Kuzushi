use super::severity::canonical_severity;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn result_summary(value: &Value) -> Option<String> {
    let chains = chain_items(value)?;
    if chains.is_empty() {
        return None;
    }
    Some(chain_summary_parts(chains).join(", "))
}

fn chain_summary_parts(chains: &[Value]) -> Vec<String> {
    let mut parts = vec![format!("{} exploit chain(s)", chains.len())];
    parts.extend(severity_summary(chains).map(|severities| format!("severity {severities}")));
    parts.extend(named_chain_summary(chains).map(|named| format!("named chains {named}")));
    parts.extend(impact_summary(chains).map(|impacts| format!("impact descriptions {impacts}")));
    parts.extend(step_summary(chains).map(|steps| format!("{steps} anchored step(s)")));
    parts
}

fn chain_items(value: &Value) -> Option<&[Value]> {
    value
        .pointer("/data/chains")
        .or_else(|| value.pointer("/data/exploitChains"))
        .or_else(|| value.pointer("/data/exploit_chains"))
        .or_else(|| value.get("chains"))
        .or_else(|| value.get("exploitChains"))
        .or_else(|| value.get("exploit_chains"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn severity_summary(chains: &[Value]) -> Option<String> {
    let mut counts = BTreeMap::new();
    for chain in chains {
        let Some(severity) = string_at(chain, &["overallSeverity", "overall_severity"]) else {
            continue;
        };
        *counts.entry(canonical_severity(severity)).or_insert(0usize) += 1;
    }
    let segments = ["critical", "high", "medium", "low", "info"]
        .iter()
        .filter_map(|severity| count_segment(severity, counts.get(*severity)))
        .collect::<Vec<_>>();
    (!segments.is_empty()).then(|| segments.join(", "))
}

fn named_chain_summary(chains: &[Value]) -> Option<usize> {
    let count = chains
        .iter()
        .filter(|chain| string_at(chain, &["name", "title"]).is_some())
        .count();
    (count > 0).then_some(count)
}

fn impact_summary(chains: &[Value]) -> Option<usize> {
    let count = chains
        .iter()
        .filter(|chain| string_at(chain, &["impactDescription", "impact_description"]).is_some())
        .count();
    (count > 0).then_some(count)
}

fn step_summary(chains: &[Value]) -> Option<usize> {
    let count = chains
        .iter()
        .filter_map(chain_steps)
        .flatten()
        .filter(has_step_anchor)
        .count();
    (count > 0).then_some(count)
}

fn chain_steps(chain: &Value) -> Option<&Vec<Value>> {
    chain
        .get("steps")
        .or_else(|| chain.get("chainSteps"))
        .or_else(|| chain.get("chain_steps"))
        .and_then(Value::as_array)
}

fn has_step_anchor(step: &&Value) -> bool {
    string_at(step, &["filePath", "file_path"]).is_some()
        && number_at(step, &["startLine", "start_line"]).is_some()
}

fn string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_str)
}

fn number_at<'a>(value: &'a Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_u64)
}

fn count_segment(label: &str, count: Option<&usize>) -> Option<String> {
    count
        .copied()
        .filter(|count| *count > 0)
        .map(|count| format!("{label}={count}"))
}
