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
    let mut citations = validate_claim_citations(repo_root.as_ref(), claim);
    append_confirmed_claim_issues(claim, &citations.verified, &mut citations.issues);
    append_forbidden_runtime_claim_issue(claim, &mut citations.issues);
    let issues = citations.issues;
    let verified_citations = citations.verified;
    let accepted = issues.is_empty();
    StaticProofValidation {
        accepted,
        requested_state: claim.requested_state,
        final_state: final_static_proof_state(accepted, claim.requested_state),
        final_verdict: final_static_proof_verdict(accepted, claim.requested_state),
        issues,
        verified_citations,
    }
}

#[derive(Default)]
struct CitationValidationState {
    issues: Vec<String>,
    verified: Vec<VerifiedStaticProofCitation>,
}

fn validate_claim_citations(repo_root: &Path, claim: &StaticProofClaim) -> CitationValidationState {
    static_proof_claim_citations(claim).fold(
        CitationValidationState::default(),
        |mut state, citation| {
            state.record(repo_root, citation);
            state
        },
    )
}

fn static_proof_claim_citations(
    claim: &StaticProofClaim,
) -> impl Iterator<Item = &StaticProofCitation> {
    claim
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
}

impl CitationValidationState {
    fn record(&mut self, repo_root: &Path, citation: &StaticProofCitation) {
        match verify_static_proof_citation(repo_root, citation) {
            Ok(verified) => self.record_verified(verified),
            Err(error) => self.issues.push(unverified_citation_issue(citation, error)),
        }
    }

    fn record_verified(&mut self, verified: VerifiedStaticProofCitation) {
        if !self.verified.contains(&verified) {
            self.verified.push(verified);
        }
    }
}

fn unverified_citation_issue(citation: &StaticProofCitation, error: anyhow::Error) -> String {
    format!(
        "citation {}:{}-{} is not verified: {error}",
        citation.file_path, citation.start_line, citation.end_line
    )
}

fn append_confirmed_claim_issues(
    claim: &StaticProofClaim,
    verified_citations: &[VerifiedStaticProofCitation],
    issues: &mut Vec<String>,
) {
    if claim.requested_state == StaticProofState::StaticallyConfirmed {
        validate_confirmed_claim_shape(claim, verified_citations, issues);
    }
}

fn append_forbidden_runtime_claim_issue(claim: &StaticProofClaim, issues: &mut Vec<String>) {
    if contains_forbidden_runtime_claim(claim) {
        issues.push(
            "whitebox-static proof must not claim runtime exploitability or exploit execution"
                .to_string(),
        );
    }
}

fn final_static_proof_state(accepted: bool, requested: StaticProofState) -> StaticProofState {
    accepted
        .then_some(requested)
        .unwrap_or(StaticProofState::NeedsRuntimeEvidence)
}

fn final_static_proof_verdict(accepted: bool, requested: StaticProofState) -> TriageVerdict {
    (accepted && requested == StaticProofState::StaticallyConfirmed)
        .then_some(TriageVerdict::TruePositive)
        .unwrap_or(TriageVerdict::NeedsReview)
}
