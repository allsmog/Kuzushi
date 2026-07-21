//! Test-only contract for the five Cockpit Spine phase compositions.
//!
//! This module owns the terminal-profile matrix for the canonical durable
//! Map, Scan, Review, Prove, and Fix screens.

use super::*;
use crate::theme;
use crate::ui_view_models::{phase_cockpit_model_for_phase, PhaseCockpitBody};
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
        .contains("record terminal dispositions for 6 of 6 ledger candidates"));
    assert_eq!(cockpit.header.next_action, journey.next_action);
    assert_eq!(cockpit.header.phase_rail, journey.phases);
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
