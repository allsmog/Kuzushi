use serde_json::Value;

/// Parse the string-keyed YAML documents Kuzushi supports into the same
/// dynamic value model used by its JSON ingestion paths.
///
/// Supported manifests use string mapping keys. Keeping that constraint at
/// this boundary lets production parsers share the maintained, safe-Rust
/// `serde-saphyr` backend without leaking parser-specific value types through
/// the scanners.
pub(crate) fn parse_value(input: &str) -> Result<Value, serde_saphyr::Error> {
    serde_saphyr::from_str(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest_scalars_sequences_and_mappings() {
        let value =
            parse_value("name: fixture\nenabled: true\ndependencies:\n  - serde\n  - anyhow\n")
                .unwrap();

        assert_eq!(value["name"], "fixture");
        assert_eq!(value["enabled"], true);
        assert_eq!(value["dependencies"][1], "anyhow");
    }

    #[test]
    fn rejects_non_string_mapping_keys_at_the_shared_boundary() {
        let error = parse_value("? [compound, key]\n: value\n").unwrap_err();

        assert!(!error.to_string().is_empty());
    }
}
