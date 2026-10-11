use super::*;
use crate::Severity;

fn row(id: i64) -> Finding {
    let mut finding = Finding::new_tool(
        "fixture",
        "owned.marker",
        "lib.rs",
        1,
        None,
        Severity::Low,
        "Owned synthetic marker",
    );
    finding.id = Some(id);
    finding.identity_id = Some("fi_owned_identity".into());
    finding
}

#[test]
fn exact_generation_wins_even_when_another_matching_generation_is_present() {
    let before = row(1);
    let after = row(2);
    let anchor = finding_page_continuity_anchor(&before);
    assert_eq!(
        finding_page_anchor_index(&[after, before], &anchor),
        Some(1)
    );
}

#[test]
fn a_unique_replacement_keeps_its_identity_and_fingerprint() {
    let anchor = finding_page_continuity_anchor(&row(1));
    let mut unrelated = row(3);
    unrelated.identity_id = Some("fi_unrelated".into());
    assert_eq!(
        finding_page_anchor_index(&[unrelated, row(2)], &anchor),
        Some(1)
    );
}

#[test]
fn ambiguous_generations_and_related_variants_cannot_be_followed_implicitly() {
    let anchor = finding_page_continuity_anchor(&row(1));
    assert_eq!(finding_page_anchor_index(&[row(2), row(3)], &anchor), None);
    let mut variant = row(2);
    variant.fingerprint = "fixture:related-variant".into();
    assert_eq!(finding_page_anchor_index(&[variant], &anchor), None);
}

#[test]
fn legacy_anchors_and_findings_without_identity_keep_exact_semantics() {
    assert_eq!(
        finding_page_anchor_index(&[row(1)], "generation:1"),
        Some(0)
    );
    assert_eq!(finding_page_anchor_index(&[row(2)], "generation:1"), None);
    let mut missing = row(1);
    missing.identity_id = None;
    assert_eq!(finding_page_continuity_anchor(&missing), "generation:1");
    missing.id = None;
    let exact = finding_page_anchor(&missing);
    assert_eq!(finding_page_anchor_index(&[missing], &exact), Some(0));
}

#[test]
fn malformed_unsupported_or_extended_tokens_do_not_repair_themselves() {
    for anchor in ["continuity:malformed", "continuity:{\"version\":2,\"exact\":\"generation:1\",\"identity\":\"fi_owned_identity\",\"fingerprint\":\"unused\"}",
        "continuity:{\"version\":1,\"exact\":\"generation:1\",\"identity\":\"fi_owned_identity\",\"fingerprint\":\"unused\",\"extra\":true}"] {
        assert_eq!(finding_page_anchor_index(&[row(1)], anchor), None);
    }
}
