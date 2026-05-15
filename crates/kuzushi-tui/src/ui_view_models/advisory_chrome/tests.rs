use super::*;
use crate::{AdvisoryState, BudgetHalt, ThrottleAdvisory};
use std::time::Instant;

#[test]
fn throttle_banner_model_copies_operator_visible_advisory_text() {
    let throttle = ThrottleAdvisory {
        source: "anthropic".to_string(),
        message: "429 retry-after 14s".to_string(),
        since: Instant::now(),
    };

    let model = ThrottleBannerModel::from_advisory(&throttle);

    assert_eq!(model.source, "anthropic");
    assert_eq!(model.message, "429 retry-after 14s");
}

#[test]
fn cost_cap_halt_model_formats_spend_against_limit() {
    let halt = BudgetHalt {
        limit_usd: 1.0,
        spent_usd: 1.5,
    };

    let model = CostCapHaltModel::from_halt(&halt);

    assert_eq!(
        model.header,
        "■ COST CAP HALT · spent $1.5000 / cap $1.0000"
    );
}

#[test]
fn advisory_models_are_absent_without_active_advisories() {
    let app = ShellApp {
        advisory: AdvisoryState::default(),
        ..ShellApp::new(kuzushi_core::V2Config::default(), None)
    };

    assert!(throttle_banner_model(&app).is_none());
    assert!(cost_cap_halt_model(&app).is_none());
}
