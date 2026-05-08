#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn scope_sets_persists_and_clears_vendor_assessment_scope() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };

        let updated = scope(
            json!({
                "vendorName": "Acme",
                "productName": "Acme AI",
                "profile": "enterprise-ai"
            }),
            &ctx,
        )
        .unwrap();
        assert_eq!(
            updated.pointer("/data/scope/vendorName"),
            Some(&json!("Acme"))
        );
        assert!(workspace
            .root()
            .join(".kuzushi/vendor-assessment/scope.json")
            .exists());

        let cleared = scope(json!({"clear": true}), &ctx).unwrap();
        assert_eq!(cleared.pointer("/data/cleared"), Some(&json!(true)));
        assert_eq!(cleared.pointer("/data/scope/vendorName"), Some(&json!("")));
        assert_eq!(cleared.pointer("/data/scope/documents"), Some(&json!([])));
    }
}
