//! Test-only contract for the five Cockpit Spine phase compositions.
//!
//! This module owns the terminal-profile matrix for the canonical durable
//! Map, Scan, Review, Prove, and Fix screens.

use super::*;
use crate::theme;
use crate::ui_view_models::{phase_cockpit_model_for_phase, PhaseCockpitBody};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

mod assertions;
mod contract;
mod failure_snapshots;
mod fixture;
mod snapshots;

use contract::{PhaseCompositionContract, TerminalProfile, CONTRACTS, SIZES};
use fixture::PhaseReferenceFixture;

fn render_phase(
    contract: PhaseCompositionContract,
    width: u16,
    height: u16,
    profile: TerminalProfile,
) -> (Buffer, String) {
    let fixture = PhaseReferenceFixture::new(contract.page, width, height);
    let _theme = theme::scoped_theme_for_test(profile.config());
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("phase contract terminal");
    terminal
        .draw(|frame| render_app(frame, &fixture.app))
        .expect("phase contract render");
    let buffer = terminal.backend().buffer().clone();
    let text = fixture.normalize(buffer_text(&buffer));
    (buffer, text)
}

fn buffer_text(buffer: &Buffer) -> String {
    (0..buffer.area.height)
        .map(|y| buffer_row_text(buffer, y))
        .collect::<Vec<_>>()
        .join("\n")
}

fn buffer_row_text(buffer: &Buffer, y: u16) -> String {
    (0..buffer.area.width)
        .map(|x| buffer[(x, y)].symbol())
        .collect::<String>()
        .trim_end()
        .to_string()
}

#[test]
fn deterministic_reference_fixture_contains_every_required_real_projection() {
    let fixture = PhaseReferenceFixture::new(WorkbenchPage::Prove, 120, 36);
    let map = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Map);
    let scan = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Scan);
    let review = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Review);
    let prove = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Prove);
    let fix = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Fix);

    let PhaseCockpitBody::Map(map) = map.body else {
        panic!("map body")
    };
    let PhaseCockpitBody::Scan(scan) = scan.body else {
        panic!("scan body")
    };
    let PhaseCockpitBody::Review(review) = review.body else {
        panic!("review body")
    };
    let PhaseCockpitBody::Prove(prove) = prove.body else {
        panic!("prove body")
    };
    let PhaseCockpitBody::Fix(fix) = fix.body else {
        panic!("fix body")
    };
    assert!(map.context.snapshot_present);
    assert!(map.project.rows.len() >= 4);
    assert!(map.attack_surface.is_some());
    assert!(map.dfd.empty_hint.is_none());
    assert_eq!(
        scan.attempt.as_ref().map(|attempt| attempt.run_id.as_str()),
        Some("scan-phase-run")
    );
    assert_eq!(review.review.total_count, 6);
    assert!(review.finding.is_some());
    assert!(prove.attack_path.empty_hint.is_none());
    assert!(prove.proof.is_some_and(|proof| proof.has_replay()));
    assert!(fix.attack_tree.empty_hint.is_none());
    assert!(fix.dfd.empty_hint.is_none());
    assert!(fix.patch.is_some());
    assert_eq!(fix.report.counts.total_findings, 6);
}

#[test]
fn reference_header_matches_hydrated_journey_reality() {
    let fixture = PhaseReferenceFixture::new(WorkbenchPage::Map, 120, 36);
    let journey = crate::ui_view_models::journey_model(&fixture.app).expect("fixture journey");
    let cockpit = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Map);

    assert!(journey.progress.map_artifacts_built);
    assert_eq!(journey.progress.finding_total, 6);
    assert_eq!(journey.current, kuzushi_core::WorkflowPhase::Review);
    assert!(journey
        .next_action
        .contains("review 6 remaining findings (6 total)"));
    assert_eq!(cockpit.header.next_action, journey.next_action);
    assert_eq!(cockpit.header.phase_rail, journey.phases);
}

#[test]
fn ready_map_renders_the_gallery_as_its_primary_body() {
    let map = CONTRACTS
        .iter()
        .copied()
        .find(|contract| contract.page == WorkbenchPage::Map)
        .expect("Map composition contract");
    let (_, text) = render_phase(map, 160, 48, TerminalProfile::ALL[0]);

    assert!(text.contains("SYSTEM SUMMARY"), "{text}");
    assert!(text.contains("EXECUTIVE SUMMARY"), "{text}");
    assert!(text.contains("OVERALL DATA FLOW"), "{text}");
    assert!(text.contains("COMPONENT TREE"), "{text}");
    assert!(text.contains("views  [summary] · dfd"), "{text}");
    assert!(!text.contains("REPOSITORY / DATA-FLOW MAP"), "{text}");
    assert!(!text.contains("PROJECT CONTEXT · NEXT SCANS"), "{text}");
}

#[test]
fn unresolved_completed_map_keeps_the_gallery_primary_with_a_compact_receipt() {
    let mut fixture = PhaseReferenceFixture::new(WorkbenchPage::Map, 120, 36);
    let target = fixture.target().to_path_buf();
    crate::test_support::seed_fira_shaped_completed_map_attempt(&target);
    fixture.app.clear_running_tool_for_test();
    fixture.app.refresh_phase_attempt_projection();
    fixture.app.hydrate_all_view_data_for_test();

    let text = render_compact_map_result(&fixture);
    assert_compact_map_result(&fixture, &text);
    navigate_and_accept_compact_map_result(&mut fixture);
}

fn render_compact_map_result(fixture: &PhaseReferenceFixture) -> String {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).expect("compact result terminal");
    terminal
        .draw(|frame| render_app(frame, &fixture.app))
        .expect("compact result render");
    fixture.normalize(buffer_text(terminal.backend().buffer()))
}

fn assert_compact_map_result(fixture: &PhaseReferenceFixture, text: &str) {
    let plan = crate::workbench_phase_plan_for_app(
        &fixture.app,
        ratatui::layout::Rect::new(0, 0, 120, 36),
    )
    .expect("workbench plan");

    assert_ne!(plan.density, crate::ui_view_models::LayoutDensity::Guided);
    assert!(text.contains("SYSTEM SUMMARY"), "{text}");
    assert!(text.contains("RESULT READY"), "{text}");
    assert!(text.contains("Map ready"), "{text}");
    assert!(text.contains("3 run(s)"), "{text}");
    assert!(!text.contains("Recommended 5 module tool(s)"), "{text}");
    assert!(fixture
        .app
        .engagement
        .unresolved_phase_attempt(kuzushi_core::WorkflowPhase::Map)
        .is_some());
}

fn navigate_and_accept_compact_map_result(fixture: &mut PhaseReferenceFixture) {
    fixture.app.set_input_mode(crate::InputMode::Navigate);
    fixture
        .app
        .reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        fixture.app.current_map_viz_page(),
        crate::scene3d::VizPage::Dfd
    );
    fixture
        .app
        .reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::NONE));
    assert!(fixture
        .app
        .engagement
        .unresolved_phase_attempt(kuzushi_core::WorkflowPhase::Map)
        .is_none());
    assert_eq!(
        crate::ui_view_models::active_workbench_page(&fixture.app),
        WorkbenchPage::Map
    );
}

#[test]
fn phase_composition_contract_covers_120_phase_size_profile_buffers() {
    let mut count = 0;
    for contract in CONTRACTS {
        for (width, height) in SIZES {
            for profile in TerminalProfile::ALL {
                let (buffer, text) = render_phase(contract, width, height, profile);
                contract.assert_buffer(&buffer, &text, profile);
                count += 1;
            }
        }
    }
    assert_eq!(count, 120);
}

#[test]
fn scan_composition_contract_covers_reported_warp_104_by_61_viewport() {
    let scan = CONTRACTS
        .iter()
        .copied()
        .find(|contract| contract.page == WorkbenchPage::Scan)
        .expect("scan composition contract");

    for profile in TerminalProfile::ALL {
        let (buffer, text) = render_phase(scan, 104, 61, profile);
        scan.assert_buffer(&buffer, &text, profile);
    }
}

#[test]
fn plain_phase_contract_covers_all_five_phases_at_all_six_widths() {
    let mut count = 0;
    for contract in CONTRACTS {
        for (width, height) in SIZES {
            let fixture = PhaseReferenceFixture::new(contract.page, width, height);
            let rendered = render_plain_app(&fixture.app, width as usize);
            contract.assert_plain_width(&rendered, width);
            let text = fixture.normalize(rendered);
            contract.assert_plain_text(&text, width);
            count += 1;
        }
    }
    assert_eq!(count, 30);
}

#[test]
fn truecolor_phase_reference_has_30_canonical_buffer_snapshots() {
    let mut count = 0;
    for contract in CONTRACTS {
        for (width, height) in SIZES {
            let (_, text) = render_phase(contract, width, height, TerminalProfile::TrueColor);
            snapshots::assert_phase_snapshot(contract, width, height, &text);
            count += 1;
        }
    }
    assert_eq!(count, 30);
}
