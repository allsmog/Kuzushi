use super::*;

pub(super) fn threat_signal_count(threat_model: Option<&Value>) -> usize {
    threat_model
        .map(canonical_threat_document)
        .map(count_threat_model_signals)
        .unwrap_or(0)
}

pub(super) fn threat_model_dfd_count(threat_model: Option<&Value>, key: &str) -> usize {
    let Some(document) = threat_model.map(canonical_threat_document) else {
        return 0;
    };
    document
        .get("dfd")
        .and_then(|dfd| dfd_array_value(dfd, key))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

pub(super) fn threat_model_array_count(threat_model: Option<&Value>, key: &str) -> usize {
    threat_model
        .map(canonical_threat_document)
        .map(|document| json_array_len(document, key))
        .unwrap_or(0)
}

pub(super) fn threat_model_related_cwes(threat_model: Option<&Value>) -> BTreeMap<String, usize> {
    let Some(document) = threat_model.map(canonical_threat_document) else {
        return BTreeMap::new();
    };
    let mut counts = BTreeMap::new();
    let Some(threats) = document.get("threats").and_then(Value::as_array) else {
        return counts;
    };
    for threat in threats {
        collect_related_cwes(threat, &mut counts);
    }
    counts
}

fn count_threat_model_signals(document: &Value) -> usize {
    count_known_arrays(document) + count_nested_known_arrays(document)
}

fn count_nested_known_arrays(document: &Value) -> usize {
    ["dfd", "model", "threatModel"]
        .iter()
        .filter_map(|key| document.get(*key))
        .map(count_known_arrays)
        .sum()
}

fn count_known_arrays(document: &Value) -> usize {
    threat_signal_keys()
        .iter()
        .map(|key| json_array_len(document, key))
        .sum()
}

fn threat_signal_keys() -> &'static [&'static str] {
    &[
        "actors",
        "edges",
        "findings",
        "nodes",
        "scenarios",
        "securityStories",
        "stories",
        "threats",
    ]
}

fn json_array_len(document: &Value, key: &str) -> usize {
    document
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn dfd_array_value<'a>(dfd: &'a Value, key: &str) -> Option<&'a Value> {
    dfd.get(key).or_else(|| match key {
        "trustBoundaries" => dfd.get("trust_boundaries"),
        _ => None,
    })
}

fn collect_related_cwes(threat: &Value, counts: &mut BTreeMap<String, usize>) {
    let Some(cwes) = related_cwe_value(threat).and_then(Value::as_array) else {
        return;
    };
    for cwe in cwes.iter().filter_map(Value::as_str).filter(non_empty) {
        *counts.entry(cwe.to_string()).or_insert(0) += 1;
    }
}

fn related_cwe_value(threat: &Value) -> Option<&Value> {
    threat
        .get("relatedCwe")
        .or_else(|| threat.get("related_cwe"))
        .or_else(|| threat.get("cwe"))
}

fn non_empty(value: &&str) -> bool {
    !value.trim().is_empty()
}

fn canonical_threat_document(value: &Value) -> &Value {
    value
        .get("document")
        .or_else(|| value.pointer("/data/document"))
        .unwrap_or(value)
}
