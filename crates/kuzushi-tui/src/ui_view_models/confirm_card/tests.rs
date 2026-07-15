use super::*;

#[test]
fn confirm_card_model_shapes_allowable_confirm_gate() {
    let confirm = PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "curl https://acme.test".to_string(),
        rationale: Some("prove reachability".to_string()),
        allowlist: Some("project allowlist".to_string()),
        actor: Some("attacker".to_string()),
        remembered: false,
    };

    let model = ConfirmCardModel::from_confirm(&confirm);

    assert_eq!(model.header_glyph, "⚠");
    assert_eq!(model.header_label, "CONFIRM · network egress");
    assert!(!model.header_danger);
    assert_eq!(model.tool, "sandbox:run");
    assert_eq!(model.target, "curl https://acme.test");
    assert_eq!(model.actor.as_deref(), Some("attacker"));
    assert_eq!(model.rationale.as_deref(), Some("prove reachability"));
    assert_eq!(model.allowlist.as_deref(), Some("project allowlist"));
    assert!(model.allows_decision);
    assert!(model.allows_remembered_yes);
}

#[test]
fn descriptor_confirm_model_disallows_remembered_yes() {
    let confirm = PendingConfirm {
        kind: ConfirmKind::DescriptorEffect,
        tool: "recon:nmap".to_string(),
        target: "127.0.0.1".to_string(),
        rationale: Some("declared external effect".to_string()),
        allowlist: None,
        actor: None,
        remembered: false,
    };

    let model = ConfirmCardModel::from_confirm(&confirm);

    assert!(model.allows_decision);
    assert!(!model.allows_remembered_yes);
}

#[test]
fn confirm_card_model_shapes_destructive_refusal() {
    let confirm = PendingConfirm {
        kind: ConfirmKind::DestructiveVerb,
        tool: "shell:run".to_string(),
        target: "rm -rf .git".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    };

    let model = ConfirmCardModel::from_confirm(&confirm);

    assert_eq!(model.header_glyph, "✗");
    assert_eq!(model.header_label, "REFUSED · destructive verb");
    assert!(model.header_danger);
    assert!(!model.allows_decision);
    assert!(!model.allows_remembered_yes);
}
