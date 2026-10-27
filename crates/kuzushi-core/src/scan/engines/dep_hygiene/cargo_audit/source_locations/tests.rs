use super::*;
use crate::Severity;

fn finding(package: &str) -> Finding {
    Finding::new_tool(
        "cargo-audit",
        "OWNED",
        "Cargo.lock",
        1,
        None,
        Severity::Low,
        "Owned metadata",
    )
    .with_structural_locator(format!("Cargo.lock#{package}"))
}

#[test]
fn parsed_name_spans_ignore_comments_and_preserve_package_identity() {
    let source = "# café name='owned'\r\nversion=3\r\n[[package]]\r\nname='other'\r\nversion='1.0.0'\r\n[[package]]\r\nversion='1.0.0'\r\nname='owned'\r\n";
    let mut findings = [finding("owned@1.0.0"), finding("other@1.0.0")];
    let identity = findings[0].fingerprint.clone();
    PackageLocations::from_bytes(source.as_bytes()).bind(&mut findings);
    assert_eq!(findings[0].start_line, 8);
    assert_eq!(findings[1].start_line, 4);
    assert_eq!(findings[0].fingerprint, identity);
    assert_eq!(
        findings[0].symbol_locator.as_deref(),
        Some("Cargo.lock#owned@1.0.0")
    );
}

#[test]
fn separate_locked_versions_select_their_own_declaration() {
    let source =
        "[[package]]\nname='owned'\nversion='1.0.0'\n[[package]]\nname='owned'\nversion='2.0.0'\n";
    let mut findings = [finding("owned@2.0.0"), finding("owned@1.0.0")];
    PackageLocations::from_bytes(source.as_bytes()).bind(&mut findings);
    assert_eq!(findings[0].start_line, 5);
    assert_eq!(findings[1].start_line, 2);
}

#[test]
fn malformed_missing_and_ambiguous_input_does_not_invent_a_line() {
    for source in [
        b"\xff".as_slice(),
        b"not toml".as_slice(),
        b"version=3\n".as_slice(),
        b"[[package]]\nname='owned'\nversion='1.0.0'\nsource='one'\n[[package]]\nname='owned'\nversion='1.0.0'\nsource='two'\n".as_slice(),
    ] {
        let mut findings = [finding("owned@1.0.0")];
        PackageLocations::from_bytes(source).bind(&mut findings);
        assert_eq!(findings[0].start_line, 0);
        assert!(findings[0].message.contains("location is unavailable"));
    }
}

#[test]
fn an_advisory_without_a_structural_locator_stays_unlocated() {
    let mut findings = [finding("owned@1.0.0")];
    findings[0].symbol_locator = None;
    PackageLocations::from_bytes(b"[[package]]\nname='owned'\nversion='1.0.0'\n")
        .bind(&mut findings);
    assert_eq!(findings[0].start_line, 0);
}

#[test]
fn many_prefix_lines_keep_a_physical_line_instead_of_a_byte_offset() {
    let source = "# owned\n".repeat(10000) + "[[package]]\nname='owned'\nversion='1.0.0'\n";
    let mut findings = [finding("owned@1.0.0")];
    PackageLocations::from_bytes(source.as_bytes()).bind(&mut findings);
    assert_eq!(findings[0].start_line, 10002);
}
