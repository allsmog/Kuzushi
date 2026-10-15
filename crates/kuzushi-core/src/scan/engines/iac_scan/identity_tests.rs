use super::*;

#[test]
fn scoped_rebinding_preserves_structural_and_line_discriminators() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("main.tf");
    let source = IacScanFinding::new(
        root.path(),
        &path,
        10,
        IacScanKind::Terraform,
        "iac-scan/test-policy",
        Severity::Medium,
        "Owned signal",
        "Owned evidence",
    );
    for original in [
        source.clone(),
        source.with_structural_locator("resource:first".into()),
    ] {
        let mut direct = original.clone();
        direct.rebase_path(Path::new("selected"));
        let mut scoped = original.to_core_finding();
        IacScanScanner::default().rebind_scoped_finding(&mut scoped, "selected/main.tf".into());
        assert_eq!(scoped.fingerprint, direct.to_core_finding().fingerprint);
        assert_eq!(scoped.symbol_locator, original.locator);
        let previous = scoped.fingerprint.clone();
        IacScanScanner::default().rebind_scoped_finding(&mut scoped, "other/main.tf".into());
        assert_ne!(previous, scoped.fingerprint);
    }
}
