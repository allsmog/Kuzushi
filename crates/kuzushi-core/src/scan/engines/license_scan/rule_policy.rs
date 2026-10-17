use super::LicenseScanOptions;

const BASE_RULES: &[&str] = &[
    "license-scan/missing-license",
    "license-scan/strong-copyleft",
    "license-scan/weak-copyleft",
    "license-scan/missing-license-file",
    "license-scan/license-file-mismatch",
    "license-scan/spdx-header-mismatch",
];

/// Persist the enabled checks independently of which checks produced a signal.
pub(crate) fn enabled_rule_ids(options: LicenseScanOptions) -> Vec<String> {
    let mut rules = BASE_RULES
        .iter()
        .map(|rule| (*rule).to_string())
        .collect::<Vec<_>>();
    if options.require_source_spdx_headers {
        rules.push("license-scan/missing-spdx-header".into());
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_header_policy_is_recorded_only_when_enabled() {
        let optional = "license-scan/missing-spdx-header".to_string();
        let default = enabled_rule_ids(LicenseScanOptions::default());
        assert_eq!(default.len(), 6);
        assert!(!default.contains(&optional));
        let required = enabled_rule_ids(LicenseScanOptions {
            require_source_spdx_headers: true,
        });
        assert_eq!(required.len(), 7);
        assert!(required.contains(&optional));
        assert!(default.iter().all(|rule| required.contains(rule)));
    }
}
