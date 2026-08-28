use super::{is_attack_chain_finding, Finding, FindingIdentityBasis};

/// Returns the weakest basis that authorizes an automated decision to move
/// from `source` to `candidate`. Callers persist this value with the decision
/// so later audits can reconstruct why propagation was allowed.
pub fn auto_triage_propagation_basis(
    source: &Finding,
    candidate: &Finding,
) -> Option<FindingIdentityBasis> {
    if !same_identity(source, candidate) || chain_kind_differs(source, candidate) {
        return None;
    }
    let source_basis = source.effective_identity_basis();
    let candidate_basis = candidate.effective_identity_basis();
    if source.id.is_some() && source.id == candidate.id {
        return Some(conservative_basis(source_basis, candidate_basis));
    }
    if source_basis.is_strong() && candidate_basis.is_strong() {
        return Some(conservative_basis(source_basis, candidate_basis));
    }
    shared_fallback_evidence(source, candidate).then_some(FindingIdentityBasis::FileFallback)
}

fn conservative_basis(
    source: FindingIdentityBasis,
    candidate: FindingIdentityBasis,
) -> FindingIdentityBasis {
    use FindingIdentityBasis::{
        CrossRunDedupKey, ExactProducerFingerprint, FileFallback, SourceLocator,
    };
    match (source, candidate) {
        (FileFallback, _) | (_, FileFallback) => FileFallback,
        (SourceLocator, _) | (_, SourceLocator) => SourceLocator,
        (CrossRunDedupKey, _) | (_, CrossRunDedupKey) => CrossRunDedupKey,
        (ExactProducerFingerprint, ExactProducerFingerprint) => ExactProducerFingerprint,
    }
}

fn same_identity(source: &Finding, candidate: &Finding) -> bool {
    match (
        source.identity_id.as_deref(),
        candidate.identity_id.as_deref(),
    ) {
        (Some(source), Some(candidate)) => source == candidate,
        _ => source.id.is_some() && source.id == candidate.id,
    }
}

fn chain_kind_differs(source: &Finding, candidate: &Finding) -> bool {
    is_attack_chain_finding(source) != is_attack_chain_finding(candidate)
}

fn shared_fallback_evidence(source: &Finding, candidate: &Finding) -> bool {
    equal_nonempty(&source.dedup_key, &candidate.dedup_key)
        || equal_nonempty(&source.source_signature, &candidate.source_signature)
}

fn equal_nonempty(left: &Option<String>, right: &Option<String>) -> bool {
    left.as_deref()
        .filter(|value| !value.trim().is_empty())
        .zip(right.as_deref().filter(|value| !value.trim().is_empty()))
        .is_some_and(|(left, right)| left == right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: i64, basis: FindingIdentityBasis) -> Finding {
        Finding {
            id: Some(id),
            identity_id: Some("fi_shared".to_string()),
            identity_basis: Some(basis),
            tool: "semgrep".to_string(),
            rule_id: "CWE-89".to_string(),
            ..Finding::default()
        }
    }

    #[test]
    fn strong_bases_propagate_across_one_identity() {
        let source = finding(1, FindingIdentityBasis::ExactProducerFingerprint);
        let candidate = finding(2, FindingIdentityBasis::SourceLocator);

        assert_eq!(
            auto_triage_propagation_basis(&source, &candidate),
            Some(FindingIdentityBasis::SourceLocator)
        );
    }

    #[test]
    fn strong_basis_receipt_is_direction_independent() {
        let exact = finding(1, FindingIdentityBasis::ExactProducerFingerprint);
        let locator = finding(2, FindingIdentityBasis::SourceLocator);

        assert_eq!(
            auto_triage_propagation_basis(&exact, &locator),
            Some(FindingIdentityBasis::SourceLocator)
        );
        assert_eq!(
            auto_triage_propagation_basis(&locator, &exact),
            Some(FindingIdentityBasis::SourceLocator)
        );
    }

    #[test]
    fn cross_run_receipt_is_weaker_than_an_exact_fingerprint() {
        let exact = finding(1, FindingIdentityBasis::ExactProducerFingerprint);
        let dedup = finding(2, FindingIdentityBasis::CrossRunDedupKey);

        assert_eq!(
            auto_triage_propagation_basis(&exact, &dedup),
            Some(FindingIdentityBasis::CrossRunDedupKey)
        );
    }

    #[test]
    fn fallback_requires_a_matching_signature_or_dedup_key() {
        let mut source = finding(1, FindingIdentityBasis::FileFallback);
        let mut candidate = finding(2, FindingIdentityBasis::SourceLocator);
        assert_eq!(auto_triage_propagation_basis(&source, &candidate), None);

        source.source_signature = Some("app.rs:8:89".to_string());
        candidate.source_signature = source.source_signature.clone();
        assert_eq!(
            auto_triage_propagation_basis(&source, &candidate),
            Some(FindingIdentityBasis::FileFallback)
        );
    }

    #[test]
    fn attack_chain_never_propagates_into_a_component() {
        let mut chain = finding(1, FindingIdentityBasis::SourceLocator);
        chain.tool = "chains".to_string();
        chain.rule_id = "exploit-chain/auth".to_string();
        let component = finding(2, FindingIdentityBasis::SourceLocator);

        assert_eq!(auto_triage_propagation_basis(&chain, &component), None);
    }
}
