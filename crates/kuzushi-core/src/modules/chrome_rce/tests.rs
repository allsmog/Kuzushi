#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::Severity;

    #[test]
    fn hot_path_rules_preserve_ordered_specificity_and_unknown_paths() {
        let specific_maglev =
            hot_path_finding("src/v8/src/maglev/maglev-phi-representation-selector.cc").unwrap();
        assert_eq!(
            specific_maglev.rule_id,
            "chrome-rce-hot-path-v8-maglev-phi-representation-selector"
        );
        assert_eq!(specific_maglev.severity, Severity::High);

        let generic_maglev = hot_path_finding("src/v8/src/maglev/graph-builder.cc").unwrap();
        assert_eq!(generic_maglev.rule_id, "chrome-rce-hot-path-v8-maglev");
        assert_eq!(generic_maglev.severity, Severity::Medium);

        let dawn_template =
            hot_path_finding("third_party/dawn/generator/templates/dawn/wire/server/api.cpp")
                .unwrap();
        assert_eq!(
            dawn_template.rule_id,
            "chrome-rce-hot-path-dawn-wire-server-templates"
        );
        assert_eq!(dawn_template.severity, Severity::High);

        assert!(hot_path_finding("content/browser/unrelated.cc").is_none());
    }
}
