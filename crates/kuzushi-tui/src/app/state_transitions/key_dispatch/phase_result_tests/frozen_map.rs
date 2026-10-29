//! A Map built by an approved plan carries an `allowanceRef`; Refine and
//! Regenerate on it must open separately approved regeneration instead of a
//! rerun draft the allowance ledger would refuse. An exact rerun changes no
//! options, so it keeps the ordinary rerun review.
use super::*;

fn frozen_map() -> ResultCardFixture {
    ResultCardFixture::open_with_input(
        WorkflowPhase::Map,
        "threat-model:build",
        serde_json::json!({
            "mode": "build",
            "seedMode": "seeded",
            "allowanceRef": {
                "schemaVersion": 1,
                "investigationId": "investigation-1",
                "revision": 1,
                "workId": "map-1"
            }
        }),
    )
}

fn regeneration_entry_is_open(app: &ShellApp) -> bool {
    app.study_context_picker()
        .is_some_and(|picker| picker.regeneration_entry)
}

fn open_study_has_generation(app: &ShellApp) -> bool {
    app.router
        .campaign()
        .batch_scan_config
        .as_ref()
        .is_some_and(|config| config.context_generation.is_some())
}

fn assert_routed_to_regeneration(fixture: &ResultCardFixture) {
    assert!(fixture.app.engagement.pending_phase_rerun().is_none());
    assert!(
        regeneration_entry_is_open(&fixture.app),
        "{:?}",
        fixture.notice_message()
    );
}

#[test]
fn frozen_map_refine_and_regenerate_keys_open_the_regeneration_entry() {
    for command in [PhaseResultCommand::Refine, PhaseResultCommand::Regenerate] {
        let mut fixture = frozen_map();

        assert!(fixture.press(advertised_key(command)).handled);

        assert_routed_to_regeneration(&fixture);
    }
}

#[test]
fn frozen_map_regeneration_sets_aside_a_finished_study() {
    let mut fixture = frozen_map();
    fixture.app.open_finished_context_study_for_test();
    assert!(open_study_has_generation(&fixture.app));
    fixture.app.set_shell_view(ShellView::Workbench);
    fixture.app.set_input_mode(InputMode::Navigate);

    fixture
        .app
        .apply_phase_result_command(PhaseResultCommand::Regenerate);

    assert_routed_to_regeneration(&fixture);
    assert!(!open_study_has_generation(&fixture.app));
}

#[test]
fn an_exact_rerun_of_a_frozen_map_is_not_intercepted() {
    let mut fixture = frozen_map();

    assert!(
        fixture
            .press(advertised_key(PhaseResultCommand::RunAgain))
            .handled
    );

    // The ordinary rerun review owns it: its input validation consults the
    // allowance ledger (empty in this fixture) and refuses out loud, rather
    // than the card diverting into regeneration.
    let notice = fixture.notice_message().unwrap_or_default();
    assert!(notice.starts_with("rerun input is invalid"), "{notice}");
    assert!(notice.contains("approved allowance"), "{notice}");
    assert!(!regeneration_entry_is_open(&fixture.app));
    assert!(fixture.app.router.campaign().batch_scan_config.is_none());
}
