use super::*;

fn detail(finding: &Finding, alias: &str) -> FindingDetailModel {
    FindingDetailModel::from_projection(finding, project_finding(finding, Some(alias.into())), None)
}

#[test]
fn reference_names_the_recorded_generation_independently_of_list_alias_or_identity() {
    let mut finding = Finding {
        id: Some(42),
        identity_id: Some("shared-durable-identity".into()),
        ..Finding::default()
    };
    let first = detail(&finding, "F-0001");
    let reordered = detail(&finding, "F-0002");
    assert_eq!(
        first.observation_reference.as_deref(),
        Some("generation:42")
    );
    assert_eq!(first.observation_reference, reordered.observation_reference);

    finding.id = Some(43);
    let later = detail(&finding, "F-0001");
    assert_eq!(later.identity_label, first.identity_label);
    assert_eq!(later.alias, first.alias);
    assert_eq!(
        later.observation_reference.as_deref(),
        Some("generation:43")
    );
    assert_ne!(later.observation_reference, first.observation_reference);
}

#[test]
fn a_reopen_command_requires_a_valid_persisted_generation() {
    for id in [None, Some(0), Some(-1)] {
        let finding = Finding {
            id,
            ..Finding::default()
        };
        assert!(detail(&finding, "F-0001").observation_reference.is_none());
    }
}
