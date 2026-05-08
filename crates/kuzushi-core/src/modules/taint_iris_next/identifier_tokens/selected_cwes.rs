use super::*;

pub(in crate::modules::taint_iris_next) fn normalize_taint_iris_next_selections(
    items: Vec<Value>,
    catalog: &[TaintIrisNextRankedCatalogEntry],
) -> Result<Vec<Value>> {
    let catalog_ids = catalog
        .iter()
        .map(|entry| entry.cwe.clone())
        .collect::<BTreeSet<_>>();
    let mut selections = Vec::new();
    let mut rejected = Vec::new();
    for item in items {
        let Value::Object(object) = item else {
            continue;
        };
        let Some(cwe) = read_object_string(&object, &["cwe"]) else {
            continue;
        };
        let cwe = normalize_taint_next_cwe(&cwe);
        let catalog_signals =
            read_object_string_array(&object, &["catalogSignals", "catalog_signals"]);
        let custom = read_object_string(&object, &["customCweRationale", "custom_cwe_rationale"]);
        if !catalog_ids.contains(&cwe) && custom.is_none() {
            rejected.push(format!(
                "{cwe}: not present in CWE catalog and missing customCweRationale"
            ));
            continue;
        }
        if catalog_ids.contains(&cwe) && catalog_signals.is_empty() {
            rejected.push(format!(
                "{cwe}: catalog CWE selection must cite at least one catalog signal"
            ));
            continue;
        }
        selections.push(json!({
            "cwe": cwe,
            "reason": read_object_string(&object, &["reason"]).unwrap_or_default(),
            "catalogSignals": catalog_signals,
            "sourceSpec": read_object_string(&object, &["sourceSpec", "source_spec"]).unwrap_or_default(),
            "sinkSpec": read_object_string(&object, &["sinkSpec", "sink_spec"]).unwrap_or_default(),
            "sanitizerSpec": read_object_string(&object, &["sanitizerSpec", "sanitizer_spec"]).unwrap_or_default(),
            "customCweRationale": custom.unwrap_or_default(),
            "knownCatalogCwe": catalog_ids.contains(&cwe),
        }));
    }
    if !rejected.is_empty() {
        anyhow::bail!(
            "[taint-iris-next] Agent selected invalid CWEs: {}",
            rejected.join("; ")
        );
    }
    Ok(selections)
}
