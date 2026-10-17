#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn hot_path_rules_preserve_ordered_specificity_and_unknown_paths() {
        let specific_maglev = review_hint(
            "src/v8/src/maglev/maglev-phi-representation-selector.cc",
            "",
        )
        .unwrap();
        assert_eq!(
            specific_maglev.rule_id,
            "chrome-rce-hot-path-v8-maglev-phi-representation-selector"
        );
        assert!(specific_maglev.reason.contains("Source inspection"));

        let generic_maglev = review_hint("src/v8/src/maglev/graph-builder.cc", "").unwrap();
        assert_eq!(generic_maglev.rule_id, "chrome-rce-hot-path-v8-maglev");
        assert!(serde_json::to_value(&generic_maglev)
            .unwrap()
            .get("severity")
            .is_none());

        let dawn_template = review_hint(
            "third_party/dawn/generator/templates/dawn/wire/server/api.cpp",
            "",
        )
        .unwrap();
        assert_eq!(
            dawn_template.rule_id,
            "chrome-rce-hot-path-dawn-wire-server-templates"
        );
        assert!(dawn_template.reason.contains("Source inspection"));

        assert!(review_hint("content/browser/unrelated.cc", "").is_none());
    }
}
