mod projection;

use self::projection::{
    actor_values, canonical_finding_status, confidence_values, path_values, searchable_fields,
    severity_values, source_values, status_values_match,
};
use super::review_state::EffectiveReviewStateIndex;
use kuzushi_core::Finding;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SearchFacet {
    Severity,
    Source,
    Path,
    Actor,
    Confidence,
    Status,
}

const FACET_ALIASES: &[(&str, SearchFacet)] = &[
    ("sev", SearchFacet::Severity),
    ("severity", SearchFacet::Severity),
    ("source", SearchFacet::Source),
    ("tool", SearchFacet::Source),
    ("file", SearchFacet::Path),
    ("path", SearchFacet::Path),
    ("actor", SearchFacet::Actor),
    ("confidence", SearchFacet::Confidence),
    ("conf", SearchFacet::Confidence),
    ("status", SearchFacet::Status),
];

const DISPLAY_FACETS: &[(SearchFacet, &str)] = &[
    (SearchFacet::Severity, "severity"),
    (SearchFacet::Source, "source"),
    (SearchFacet::Path, "path"),
    (SearchFacet::Actor, "actor"),
    (SearchFacet::Confidence, "confidence"),
    (SearchFacet::Status, "status"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FindingSearch {
    words: Vec<String>,
    facets: BTreeMap<SearchFacet, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingFacetValue {
    pub(crate) facet: &'static str,
    pub(crate) value: String,
}

impl FindingSearch {
    pub(crate) fn parse(query: &str) -> Self {
        let mut search = Self::default();
        for token in query.split_whitespace() {
            if !search.push_facet_token(token) {
                search.words.push(token.to_ascii_lowercase());
            }
        }
        search
    }

    pub(crate) fn matches(
        &self,
        finding: &Finding,
        review_index: &EffectiveReviewStateIndex,
    ) -> bool {
        self.facets_match(finding, review_index) && self.words_match(finding)
    }

    pub(crate) fn chips(&self, capture: bool) -> Vec<String> {
        let mut chips = Vec::new();
        if !self.words.is_empty() {
            chips.push(format!("text:\"{}\"", self.words.join(" ")));
        }
        chips.extend(DISPLAY_FACETS.iter().filter_map(|(facet, label)| {
            let values = self.values(*facet);
            (!values.is_empty()).then(|| format!("{label}:{}", values.join("|")))
        }));
        if capture {
            if let Some(chip) = chips.last_mut() {
                chip.push('\u{2038}');
            } else {
                chips.push("search:\u{2038}".to_string());
            }
        }
        chips
    }

    fn push_facet_token(&mut self, token: &str) -> bool {
        let Some((name, value)) = token.split_once(':') else {
            return false;
        };
        let Some(facet) = facet_named(name) else {
            return false;
        };
        let values = value
            .split([',', '|'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        self.facets.entry(facet).or_default().extend(values);
        true
    }

    fn values(&self, facet: SearchFacet) -> &[String] {
        self.facets.get(&facet).map(Vec::as_slice).unwrap_or(&[])
    }

    fn facets_match(&self, finding: &Finding, review_index: &EffectiveReviewStateIndex) -> bool {
        values_match(
            self.values(SearchFacet::Severity),
            &severity_values(finding),
        ) && values_match(self.values(SearchFacet::Source), &source_values(finding))
            && values_match(self.values(SearchFacet::Path), &path_values(finding))
            && values_match(self.values(SearchFacet::Actor), &actor_values(finding))
            && values_match(
                self.values(SearchFacet::Confidence),
                &confidence_values(finding, review_index),
            )
            && status_values_match(
                self.values(SearchFacet::Status),
                canonical_finding_status(finding, review_index),
            )
    }

    fn words_match(&self, finding: &Finding) -> bool {
        let fields = searchable_fields(finding);
        self.words.iter().all(|word| {
            fields.iter().any(|field| {
                field.contains(word)
                    || kuzushi_core::text::fuzzy::subsequence_score(field, word).is_some()
            })
        })
    }
}

pub(crate) fn finding_facet_values(
    finding: &Finding,
    review_index: &EffectiveReviewStateIndex,
) -> Vec<FindingFacetValue> {
    projection::finding_facet_values(finding, review_index)
}

fn facet_named(name: &str) -> Option<SearchFacet> {
    FACET_ALIASES
        .iter()
        .find_map(|(alias, facet)| alias.eq_ignore_ascii_case(name).then_some(*facet))
}

fn values_match(wanted: &[String], actual: &[String]) -> bool {
    wanted.is_empty()
        || wanted
            .iter()
            .any(|wanted| actual.iter().any(|actual| actual.contains(wanted)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::findings::{FindingSource, VulnSource};
    use kuzushi_core::{FindingEvidence, Severity, StaticProofState};

    fn finding(title: &str) -> Finding {
        let mut finding = Finding::new_tool(
            "carlini-threat-hunt",
            "gateway/ownership",
            "src/gateway.go",
            42,
            None,
            Severity::High,
            title,
        );
        finding.actor_fingerprint = Some("carlini-threat-hunt:RouterRPC:0".to_string());
        finding
    }

    fn review_index(findings: &[Finding]) -> EffectiveReviewStateIndex {
        EffectiveReviewStateIndex::from_findings_and_decisions(findings, &[])
    }

    #[test]
    fn free_text_matches_evidence_and_corroborating_sources() {
        let mut finding = finding("proxy request trusts caller input");
        finding.message = "authorization guard is absent".to_string();
        finding.evidence.push(FindingEvidence {
            kind: "code".to_string(),
            file_path: "src/dispatch.go".to_string(),
            line: 44,
            snippet: "dispatch(in.Uuid)".to_string(),
            rationale: "tenant ownership is never checked".to_string(),
            confidence: 92,
            request_blob: None,
            response_blob: None,
        });
        finding.sources.push(FindingSource {
            tool: "codeql".to_string(),
            vuln_source: Some(VulnSource::Sarif),
            source_signature: "remote-flow:ForwardRequest".to_string(),
            first_scan_id: "scan-1".to_string(),
            last_scan_id: "scan-1".to_string(),
            first_seen_at: String::new(),
            last_seen_at: String::new(),
        });
        let index = review_index(std::slice::from_ref(&finding));

        assert!(FindingSearch::parse("caller").matches(&finding, &index));
        assert!(FindingSearch::parse("authorization").matches(&finding, &index));
        assert!(FindingSearch::parse("gateway/ownership").matches(&finding, &index));
        assert!(FindingSearch::parse("gateway.go").matches(&finding, &index));
        assert!(FindingSearch::parse("dispatch uuid").matches(&finding, &index));
        assert!(FindingSearch::parse("tenant never checked").matches(&finding, &index));
        assert!(FindingSearch::parse("remote-flow").matches(&finding, &index));
        assert!(FindingSearch::parse("source:codeql file:dispatch").matches(&finding, &index));
    }

    #[test]
    fn facets_support_aliases_and_multiple_values() {
        let finding = finding("proxy request");
        let index = review_index(std::slice::from_ref(&finding));

        assert!(FindingSearch::parse(
            "sev:critical,high source:codeql|carlini path:gateway actor:gateway conf:unknown status:open"
        )
        .matches(&finding, &index));
        assert!(FindingSearch::parse("severity:low severity:high").matches(&finding, &index));
        assert!(!FindingSearch::parse("severity:low,medium").matches(&finding, &index));
        assert!(!FindingSearch::parse("status:not-a-status").matches(&finding, &index));
    }

    #[test]
    fn canonical_status_uses_proof_truth_instead_of_debug_text() {
        let mut verified = finding("verified");
        verified.static_proof_state = Some(StaticProofState::StaticallyConfirmed);
        let mut rejected = finding("rejected");
        rejected.static_proof_state = Some(StaticProofState::StaticallyRejected);
        let findings = vec![verified.clone(), rejected.clone()];
        let index = review_index(&findings);

        assert!(FindingSearch::parse("status:verified").matches(&verified, &index));
        assert!(FindingSearch::parse("status:rejected").matches(&rejected, &index));
        assert!(!FindingSearch::parse("status:open").matches(&rejected, &index));
    }
}
