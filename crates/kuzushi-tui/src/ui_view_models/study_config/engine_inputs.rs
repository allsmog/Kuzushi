use kuzushi_core::capabilities::campaign::BatchEquivalenceComponents;
use std::collections::BTreeSet;

pub(super) fn source_lines(components: &BatchEquivalenceComponents) -> Vec<String> {
    let mut facts = BTreeSet::new();
    append_identity(
        &mut facts,
        &components.engine_identity.requested_selection,
        components.engine_identity.cache_identity.as_deref(),
    );
    facts.into_iter().collect()
}

fn append_identity(
    facts: &mut BTreeSet<String>,
    selection: &serde_json::Value,
    cache: Option<&str>,
) {
    if let Some(executables) = selection["executables"].as_array() {
        facts.extend(executables.iter().map(executable_fact));
    }
    facts.insert(cache.map_or_else(
        || "Engine caches: none recorded".into(),
        |digest| format!("Recorded engine cache identity: {digest}"),
    ));
}

fn executable_fact(value: &serde_json::Value) -> String {
    let name = value["name"].as_str().unwrap_or("Unnamed engine");
    if value["status"] == "missing" {
        return format!("{name}: missing at preparation");
    }
    let Some(path) = value["path"].as_str() else {
        return format!("{name}: executable identity incomplete");
    };
    let Some(digest) = value["sha256"].as_str() else {
        return format!("{name}: executable identity incomplete");
    };
    format!("{name}: located at {path}\nRecorded content: {digest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn engine_facts_preserve_missing_incomplete_and_located_states() {
        assert_eq!(
            executable_fact(&json!({"name":"cargo-audit","status":"missing"})),
            "cargo-audit: missing at preparation"
        );
        assert!(
            executable_fact(&json!({"name":"semgrep","path":"/owned/tool"}))
                .contains("identity incomplete")
        );
        let located = executable_fact(
            &json!({"name":"semgrep","path":"/owned/tool","sha256":"sha256:recorded"}),
        );
        assert!(located.contains("/owned/tool") && located.contains("sha256:recorded"));
        assert!(!located.contains("ready"));
    }

    #[test]
    fn repeated_case_facts_are_deduplicated_and_cache_absence_stays_explicit() {
        let selection = json!({"executables":[{"name":"cargo-audit","status":"missing"}]});
        let mut facts = BTreeSet::new();
        append_identity(&mut facts, &selection, None);
        append_identity(&mut facts, &selection, None);
        assert_eq!(facts.len(), 2);
        assert!(facts.contains("Engine caches: none recorded"));
    }
}
