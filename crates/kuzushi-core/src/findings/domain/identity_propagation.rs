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
    weak_generation_basis(source, candidate, source_basis, candidate_basis)
}

/// The basis for a pair that is not strong on both sides: shared fallback
/// evidence, or an allocator-recorded exact-fingerprint rescue.
fn weak_generation_basis(
    source: &Finding,
    candidate: &Finding,
    source_basis: FindingIdentityBasis,
    candidate_basis: FindingIdentityBasis,
) -> Option<FindingIdentityBasis> {
    // Preserve the weakest independently sufficient evidence first. If the
    // two observations already share the line/source-sensitive fallback
    // evidence, that is what authorized propagation even when a later
    // observation also carries an allocator-granted exact-fingerprint basis.
    if shared_fallback_evidence(source, candidate) {
        return Some(FindingIdentityBasis::FileFallback);
    }
    // A finding can be minted with only the file-fallback basis on its first
    // observation, then rediscovered with the exact same producer fingerprint.
    // The identity allocator records the later observation with the exact
    // fingerprint basis; only that recorded strong basis may rescue a weak
    // generation when no weaker fallback evidence already authorizes it.
    // Fingerprint equality by itself must not invent a stronger receipt for
    // two rows whose persisted basis is still only file fallback.
    (has_exact_fingerprint_basis(source_basis, candidate_basis)
        && same_nonempty_fingerprint(source, candidate))
    .then_some(FindingIdentityBasis::ExactProducerFingerprint)
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

fn has_exact_fingerprint_basis(
    source: FindingIdentityBasis,
    candidate: FindingIdentityBasis,
) -> bool {
    matches!(source, FindingIdentityBasis::ExactProducerFingerprint)
        || matches!(candidate, FindingIdentityBasis::ExactProducerFingerprint)
}

fn same_nonempty_fingerprint(source: &Finding, candidate: &Finding) -> bool {
    !source.fingerprint.trim().is_empty() && source.fingerprint == candidate.fingerprint
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
    fn matching_fingerprint_does_not_overstate_an_existing_strong_basis() {
        let mut exact = finding(1, FindingIdentityBasis::ExactProducerFingerprint);
        let mut locator = finding(2, FindingIdentityBasis::SourceLocator);
        exact.fingerprint = "fp-same-producer".to_string();
        locator.fingerprint = exact.fingerprint.clone();

        assert_eq!(
            auto_triage_propagation_basis(&exact, &locator),
            Some(FindingIdentityBasis::SourceLocator)
        );
    }

    #[test]
    fn matching_fingerprint_upgrades_a_weak_first_generation() {
        let mut source = finding(1, FindingIdentityBasis::FileFallback);
        let mut candidate = finding(2, FindingIdentityBasis::ExactProducerFingerprint);
        source.fingerprint = "fp-same-producer".to_string();
        candidate.fingerprint = source.fingerprint.clone();

        assert_eq!(
            auto_triage_propagation_basis(&source, &candidate),
            Some(FindingIdentityBasis::ExactProducerFingerprint)
        );
        assert_eq!(
            auto_triage_propagation_basis(&candidate, &source),
            Some(FindingIdentityBasis::ExactProducerFingerprint)
        );
    }

    #[test]
    fn matching_fingerprint_keeps_fallback_when_fallback_evidence_already_authorizes() {
        let mut source = finding(1, FindingIdentityBasis::FileFallback);
        let mut candidate = finding(2, FindingIdentityBasis::ExactProducerFingerprint);
        source.fingerprint = "fp-same-producer".to_string();
        candidate.fingerprint = source.fingerprint.clone();
        source.dedup_key = Some("line-sensitive-key".to_string());
        candidate.dedup_key = source.dedup_key.clone();

        assert_eq!(
            auto_triage_propagation_basis(&source, &candidate),
            Some(FindingIdentityBasis::FileFallback)
        );
        assert_eq!(
            auto_triage_propagation_basis(&candidate, &source),
            Some(FindingIdentityBasis::FileFallback)
        );
    }

    #[test]
    fn matching_fingerprint_never_crosses_the_durable_identity_boundary() {
        let mut source = finding(1, FindingIdentityBasis::FileFallback);
        let mut candidate = finding(2, FindingIdentityBasis::ExactProducerFingerprint);
        source.fingerprint = "fp-same-producer".to_string();
        candidate.fingerprint = source.fingerprint.clone();
        candidate.identity_id = Some("fi_other".to_string());

        assert_eq!(auto_triage_propagation_basis(&source, &candidate), None);
    }

    #[test]
    fn matching_fingerprint_does_not_upgrade_two_fallback_generations() {
        let mut source = finding(1, FindingIdentityBasis::FileFallback);
        let mut candidate = finding(2, FindingIdentityBasis::FileFallback);
        source.fingerprint = "fp-same-producer".to_string();
        candidate.fingerprint = source.fingerprint.clone();

        assert_eq!(auto_triage_propagation_basis(&source, &candidate), None);
    }

    #[test]
    fn empty_fingerprint_never_upgrades_a_weak_generation() {
        let source = finding(1, FindingIdentityBasis::FileFallback);
        let candidate = finding(2, FindingIdentityBasis::ExactProducerFingerprint);

        assert_eq!(auto_triage_propagation_basis(&source, &candidate), None);
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
