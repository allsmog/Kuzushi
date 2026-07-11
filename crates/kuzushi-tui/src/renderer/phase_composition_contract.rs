//! Test-only contract for the four PDF-native phase compositions.
//!
//! The 114 Atlas states remain owned by the parity suite. This module owns
//! the separate 4 phases x 4 sizes x 4 terminal profiles PDF contract.

use super::*;
use crate::theme;
use crate::ui_view_models::{phase_cockpit_model_for_phase, PhaseCockpitBody};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

mod assertions;
mod contract;
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
    let fixture = PhaseReferenceFixture::new(WorkbenchPage::Review, 120, 36);
    let map = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Map);
    let hunt = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Hunt);
    let confirm = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Confirm);
    let fix = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Fix);

    let PhaseCockpitBody::Map(map) = map.body else {
        panic!("map body")
    };
    let PhaseCockpitBody::Hunt(hunt) = hunt.body else {
        panic!("hunt body")
    };
    let PhaseCockpitBody::Confirm(confirm) = confirm.body else {
        panic!("confirm body")
    };
    let PhaseCockpitBody::Fix(fix) = fix.body else {
        panic!("fix body")
    };
    assert_eq!(map.console.len(), 10);
    assert_eq!(map.task_counts.total, 2);
    assert_eq!(map.artifact_metrics.len(), 4);
    assert_eq!(hunt.review.total_count, 6);
    assert_eq!(heatmap_total(&hunt.heatmap), 6);
    assert!(confirm.attack_path.empty_hint.is_none());
    assert!(confirm.proof.is_some_and(|proof| proof.has_replay()));
    assert!(fix.attack_tree.empty_hint.is_none());
    assert!(fix.dfd.empty_hint.is_none());
    assert!(fix.patch.is_some());
    assert_eq!(fix.report.counts.total_findings, 6);
}

fn heatmap_total(heatmap: &crate::ui_view_models::FindingsHeatmap) -> u32 {
    heatmap.rows.iter().flat_map(|row| row.counts).sum()
}

#[test]
fn reference_header_matches_hydrated_journey_reality() {
    let fixture = PhaseReferenceFixture::new(WorkbenchPage::Terrain, 120, 36);
    let journey = crate::ui_view_models::journey_model(&fixture.app).expect("fixture journey");
    let cockpit = phase_cockpit_model_for_phase(&fixture.app, kuzushi_core::WorkflowPhase::Map);

    assert!(journey.progress.map_artifacts_built);
    assert_eq!(journey.progress.finding_total, 6);
    assert_eq!(journey.current, kuzushi_core::WorkflowPhase::Confirm);
    assert!(journey.next_action.contains("6 of 6 findings need review"));
    assert_eq!(cockpit.header.next_action, journey.next_action);
    assert_eq!(cockpit.header.phase_rail, journey.phases);
}

#[test]
fn phase_composition_contract_covers_64_phase_size_profile_buffers() {
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
    assert_eq!(count, 64);
}

#[test]
fn plain_phase_contract_covers_all_four_phases_at_all_four_widths() {
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
    assert_eq!(count, 16);
}

#[test]
fn truecolor_phase_reference_has_16_canonical_buffer_snapshots() {
    let mut count = 0;
    for contract in CONTRACTS {
        for (width, height) in SIZES {
            let (_, text) = render_phase(contract, width, height, TerminalProfile::TrueColor);
            snapshots::assert_phase_snapshot(contract, width, height, &text);
            count += 1;
        }
    }
    assert_eq!(count, 16);
}
