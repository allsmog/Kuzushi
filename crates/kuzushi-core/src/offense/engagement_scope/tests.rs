use super::*;

fn authorized_scope(in_scope: &[&str]) -> EngagementScope {
    EngagementScope {
        authorized: true,
        authorization_ref: "HTB:lab".to_string(),
        in_scope: in_scope.iter().map(|raw| ScopeEntry::parse(raw).unwrap()).collect(),
        ..Default::default()
    }
}

fn decide(scope: &EngagementScope, target: &str) -> ScopeDecision {
    scope.decide(&ScopeTarget::parse(target), 1_000)
}

#[test]
fn default_scope_denies_everything() {
    let scope = EngagementScope::default();
    let decision = decide(&scope, "10.0.0.5");
    assert!(!decision.is_allowed());
    assert_eq!(decision.reason(), Some("engagement scope is not marked authorized"));
}

#[test]
fn authorized_scope_requires_a_reference() {
    let scope = EngagementScope {
        authorized: true,
        in_scope: vec![ScopeEntry::parse("10.0.0.5").unwrap()],
        ..Default::default()
    };
    let decision = decide(&scope, "10.0.0.5");
    assert!(!decision.is_allowed());
    assert!(decision.reason().unwrap().contains("authorizationRef"));
}

#[test]
fn in_scope_ip_is_allowed_and_others_denied() {
    let scope = authorized_scope(&["10.0.0.5"]);
    assert!(decide(&scope, "10.0.0.5").is_allowed());
    assert!(!decide(&scope, "10.0.0.6").is_allowed());
}

#[test]
fn ipv4_cidr_matches_its_range_only() {
    let scope = authorized_scope(&["10.0.0.0/24"]);
    assert!(decide(&scope, "10.0.0.200").is_allowed());
    assert!(!decide(&scope, "10.0.1.1").is_allowed());
}

#[test]
fn ipv6_cidr_matches_its_range_only() {
    let scope = authorized_scope(&["2001:db8::/32"]);
    assert!(decide(&scope, "2001:db8:abcd::1").is_allowed());
    assert!(!decide(&scope, "2001:db9::1").is_allowed());
}

#[test]
fn bare_host_matches_itself_and_subdomains() {
    let scope = authorized_scope(&["example.com"]);
    assert!(decide(&scope, "example.com").is_allowed());
    assert!(decide(&scope, "app.staging.example.com").is_allowed());
    assert!(!decide(&scope, "evil-example.com").is_allowed());
    assert!(!decide(&scope, "notexample.com").is_allowed());
}

#[test]
fn wildcard_host_matches_subdomains_only() {
    let scope = authorized_scope(&["*.example.com"]);
    assert!(decide(&scope, "api.example.com").is_allowed());
    assert!(!decide(&scope, "example.com").is_allowed());
}

#[test]
fn exclusions_win_over_in_scope() {
    let mut scope = authorized_scope(&["10.0.0.0/24"]);
    scope.exclusions = vec![ScopeEntry::parse("10.0.0.53").unwrap()];
    assert!(decide(&scope, "10.0.0.10").is_allowed());
    let denied = decide(&scope, "10.0.0.53");
    assert!(!denied.is_allowed());
    assert!(denied.reason().unwrap().contains("excluded"));
}

#[test]
fn target_outside_the_window_is_denied() {
    let mut scope = authorized_scope(&["10.0.0.5"]);
    scope.window = Some(ScopeWindow {
        not_before_unix: Some(500),
        not_after_unix: Some(900),
    });
    // now = 1000 in `decide`, which is past not_after.
    let denied = decide(&scope, "10.0.0.5");
    assert!(!denied.is_allowed());
    assert!(denied.reason().unwrap().contains("window"));
    // Inside the window the same target is allowed.
    assert!(scope.decide(&ScopeTarget::parse("10.0.0.5"), 600).is_allowed());
}

#[test]
fn host_target_never_matches_an_ip_entry() {
    let scope = authorized_scope(&["10.0.0.5"]);
    assert!(!decide(&scope, "box.htb").is_allowed());
}

#[test]
fn invalid_cidr_prefix_is_rejected_at_parse() {
    assert!(ScopeEntry::parse("10.0.0.0/40").is_err());
    assert!(ScopeEntry::parse("2001:db8::/200").is_err());
}

#[test]
fn scope_round_trips_through_json() {
    let json = serde_json::json!({
        "authorized": true,
        "authorizationRef": "engagement-42",
        "inScope": ["10.0.0.0/24", "*.staging.example.com", "box.htb"],
        "exclusions": ["10.0.0.1"],
        "window": {"notBeforeUnix": 100, "notAfterUnix": 200}
    });
    let scope: EngagementScope = serde_json::from_value(json.clone()).unwrap();
    assert!(scope.authorized);
    assert_eq!(scope.in_scope.len(), 3);
    assert!(scope.decide(&ScopeTarget::parse("10.0.0.9"), 150).is_allowed());
    assert!(!scope.decide(&ScopeTarget::parse("10.0.0.1"), 150).is_allowed());
    // Re-serializing yields entries back as their string tokens.
    let reserialized = serde_json::to_value(&scope).unwrap();
    assert_eq!(reserialized["inScope"][0], "10.0.0.0/24");
}
