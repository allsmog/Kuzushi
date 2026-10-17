use super::*;
use crate::findings::{FindingIdentityBasis, Severity};

fn observation(id: i64, fingerprint: &str, basis: FindingIdentityBasis) -> Finding {
    let mut row = Finding::new_tool(
        "owned",
        fingerprint,
        "source.rs",
        1,
        None,
        Severity::Info,
        "Labeled fixture",
    );
    row.id = Some(id);
    row.identity_id = Some("shared-identity".into());
    row.identity_basis = Some(basis);
    row.source_signature = Some(format!("owned-signature-{fingerprint}"));
    row.dedup_key = None;
    row
}

#[test]
fn membership_follows_the_same_group_that_selects_the_global_representative() {
    let first = observation(1, "member", FindingIdentityBasis::ExactProducerFingerprint);
    let next = observation(
        2,
        "outside-later",
        FindingIdentityBasis::ExactProducerFingerprint,
    );
    let rows = vec![first, next.clone()];
    for policy in [IdentityFoldPolicy::Safe, IdentityFoldPolicy::Aggressive] {
        assert_eq!(
            representative_fingerprints_for_members(rows.clone(), policy, &BTreeSet::from([1])),
            BTreeSet::from([next.fingerprint.clone()])
        );
        assert_eq!(
            project_finding_generations(rows.clone(), policy)[0].fingerprint,
            next.fingerprint
        );
    }
}

#[test]
fn safe_membership_does_not_widen_to_an_unrelated_weak_identity() {
    let first = observation(1, "member", FindingIdentityBasis::FileFallback);
    let next = observation(2, "outside", FindingIdentityBasis::FileFallback);
    assert_eq!(
        representative_fingerprints_for_members(
            vec![first.clone(), next],
            IdentityFoldPolicy::Safe,
            &BTreeSet::from([1])
        ),
        BTreeSet::from([first.fingerprint])
    );
}
