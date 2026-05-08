#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn scope_sets_persists_and_clears_vendor_assessment_scope() {
        let temp = tempfile::tempdir().unwrap();

        let updated = scope(
            temp.path(),
            ScopeUpdate {
                vendor_name: Some("Acme".to_string()),
                product_name: Some("Acme AI".to_string()),
                profile: Some("enterprise-ai".to_string()),
                ..ScopeUpdate::default()
            },
            false,
        )
        .unwrap();
        assert_eq!(
            updated.pointer("/data/scope/vendorName"),
            Some(&json!("Acme"))
        );
        assert!(temp
            .path()
            .join(".kuzushi/vendor-assessment/scope.json")
            .exists());

        let cleared = scope(temp.path(), ScopeUpdate::default(), true).unwrap();
        assert_eq!(cleared.pointer("/data/cleared"), Some(&json!(true)));
        assert_eq!(cleared.pointer("/data/scope/vendorName"), Some(&json!("")));
        assert_eq!(cleared.pointer("/data/scope/documents"), Some(&json!([])));
    }
}
