use super::prelude::*;
use super::*;

impl StaticProofCitation {
    pub fn new(file_path: impl Into<String>, start_line: u32, end_line: u32) -> Self {
        Self {
            file_path: file_path.into(),
            start_line,
            end_line,
            snippet: None,
            snippet_hash: None,
        }
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_snippet_hash(mut self, snippet_hash: impl Into<String>) -> Self {
        self.snippet_hash = Some(snippet_hash.into());
        self
    }
}

pub fn validate_static_proof_claim(
    repo_root: impl AsRef<Path>,
    claim: &StaticProofClaim,
) -> StaticProofValidation {
    let mut issues = Vec::new();
    let mut verified_citations = Vec::new();

    for citation in claim
        .citations
        .iter()
        .chain(
            claim
                .source_or_entrypoint_evidence
                .iter()
                .filter_map(|evidence| evidence.citation.as_ref()),
        )
        .chain(
            claim
                .sink_evidence
                .iter()
                .filter_map(|evidence| evidence.citation.as_ref()),
        )
    {
        match verify_static_proof_citation(repo_root.as_ref(), citation) {
            Ok(verified) => {
                if !verified_citations.contains(&verified) {
                    verified_citations.push(verified);
                }
            }
            Err(error) => issues.push(format!(
                "citation {}:{}-{} is not verified: {error}",
                citation.file_path, citation.start_line, citation.end_line
            )),
        }
    }

    if claim.requested_state == StaticProofState::StaticallyConfirmed {
        validate_confirmed_claim_shape(claim, &verified_citations, &mut issues);
    }

    if contains_forbidden_runtime_claim(claim) {
        issues.push(
            "whitebox-static proof must not claim runtime exploitability or exploit execution"
                .to_string(),
        );
    }

    let accepted = issues.is_empty();
    StaticProofValidation {
        accepted,
        requested_state: claim.requested_state,
        final_state: if accepted {
            claim.requested_state
        } else {
            StaticProofState::NeedsRuntimeEvidence
        },
        final_verdict: if accepted && claim.requested_state == StaticProofState::StaticallyConfirmed
        {
            TriageVerdict::TruePositive
        } else {
            TriageVerdict::NeedsReview
        },
        issues,
        verified_citations,
    }
}
