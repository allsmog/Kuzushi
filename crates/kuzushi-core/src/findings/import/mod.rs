//! M2 §2.3 — bug-bounty HTTP evidence importers.
//!
//! These adapters parse Burp Suite XML and HAR captures into the
//! canonical `Finding` shape with `http-request` evidence. They live
//! under `findings::import` because the output is a Finding, not a
//! recon artefact — HTTP evidence belongs in the findings ledger so
//! triage/verify/patch workflows can reference it.

mod burp_xml;
mod capture_payload;
mod har;
mod ledger_jsonl;

/// Per-entry accounting shared by the capture importers. Every entry a
/// capture carried lands in exactly one counter, so the numbers a summary
/// reports add up to the entry count the operator can see in Burp or their
/// browser's network panel.
#[derive(Debug, Default, Clone, Copy)]
struct CaptureTally {
    imported: usize,
    skipped_out_of_scope: usize,
    skipped_unusable: usize,
}

/// Say why a capture import dropped entries, in a stable order, so no surface
/// has to invent its own accounting vocabulary. `None` when every entry became
/// a finding; the caller supplies the punctuation around the phrase.
pub fn capture_skip_phrase(out_of_scope: usize, unusable: usize) -> Option<String> {
    let mut reasons = Vec::new();
    if out_of_scope > 0 {
        reasons.push(format!("{out_of_scope} out-of-scope"));
    }
    if unusable > 0 {
        reasons.push(format!("{unusable} without a URL"));
    }
    (!reasons.is_empty()).then(|| format!("{} skipped", reasons.join(", ")))
}

pub use burp_xml::import_burp_xml;
pub use har::import_har;
pub use ledger_jsonl::import_ledger_jsonl;

#[cfg(test)]
mod tests {
    use super::capture_skip_phrase;

    #[test]
    fn a_complete_import_has_nothing_to_disclose() {
        assert_eq!(capture_skip_phrase(0, 0), None);
    }

    #[test]
    fn every_drop_reason_is_named_in_a_stable_order() {
        assert_eq!(
            capture_skip_phrase(2, 0).as_deref(),
            Some("2 out-of-scope skipped")
        );
        assert_eq!(
            capture_skip_phrase(0, 3).as_deref(),
            Some("3 without a URL skipped")
        );
        assert_eq!(
            capture_skip_phrase(2, 3).as_deref(),
            Some("2 out-of-scope, 3 without a URL skipped")
        );
    }
}
