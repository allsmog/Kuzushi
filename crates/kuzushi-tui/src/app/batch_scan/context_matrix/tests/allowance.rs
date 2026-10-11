use super::*;
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};

fn recorded_allowance() -> AllowanceSnapshot {
    AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "accounting".into(),
        revision: 1,
        model: "openai-codex:gpt-5.5".into(),
        limits: AllowanceLimits {
            max_provider_calls: 11,
            protected_review_calls: 2,
        },
        committed_calls: 9,
        review_calls: 0,
        unresolved_calls: 1,
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    }
}

#[test]
fn missing_or_failed_accounting_never_resets_prior_calls_or_operator_limits() {
    let (_root, mut app) = fixture();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    let prior = recorded_allowance();
    config.study.allowance = Some(prior.clone());
    config.study.max_provider_calls = Some(15);
    for result in [Ok(None), Err(anyhow::anyhow!("reader failed"))] {
        apply_matrix_allowance_read(config, result);
        assert_eq!(config.study.allowance.as_ref(), Some(&prior));
        assert_eq!(config.study.max_provider_calls, Some(15));
        assert!(config.study.ensure_accounting_ready().is_err());
        assert!(!config.study.approved());
    }
    apply_matrix_allowance_read(config, Ok(Some(prior.clone())));
    assert!(config.study.ensure_accounting_ready().is_ok());
    assert_eq!(config.study.allowance.as_ref(), Some(&prior));
    assert_eq!(config.study.max_provider_calls, Some(15));
    assert_eq!(config.study.protected_review_calls, Some(2));
}

#[test]
fn an_unapproved_fresh_matrix_is_described_as_unapproved() {
    let (_root, mut app) = fixture();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    apply_matrix_allowance_read(config, Ok(None));
    assert!(config.study.allowance.is_none());
    assert!(!config.study.approved());
    assert!(config
        .notice
        .as_deref()
        .unwrap()
        .starts_with("Allowance not approved."));
}
