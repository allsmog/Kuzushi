import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import assert from 'node:assert/strict';
const staged = new Map();
function edit(path, before, after) {
  const text = staged.get(path) ?? readFileSync(path, 'utf8');
  assert.equal(text.split(before).length - 1, 1, `expected one exact edit anchor: ${path}: ${before.slice(0, 70)}`);
  staged.set(path, text.replace(before, after));
}
function append(path, text) { staged.set(path, (staged.get(path) ?? readFileSync(path, 'utf8')) + text); }
const tui = 'crates/kuzushi-tui/src/';
edit(tui + 'app/state_transitions/key_dispatch.rs',
`    /// Phase whose unresolved RESULT READY attempt the result-card keys act
    /// on. Prefer the page in view; when reality derivation has moved the
    /// page away from the phase that actually finished (e.g. a Map result
    /// while prior findings derive Review), fall back to the earliest phase
    /// with an unresolved attempt — advertised keys must work where
    /// advertised.
    pub(crate) fn phase_result_target_phase(&self) -> Option<WorkflowPhase> {
        let page_phase = crate::ui_view_models::active_workbench_page(self).phase();
        if self
            .engagement
            .unresolved_phase_attempt(page_phase)
            .is_some()
        {
            return Some(page_phase);
        }
        WorkflowPhase::ORDER
            .iter()
            .copied()
            .find(|phase| self.engagement.unresolved_phase_attempt(*phase).is_some())
    }`,
`    /// Result ownership follows the displayed workbench page. An unresolved
    /// attempt on another page remains durable and inspectable, but cannot
    /// capture this page's keyboard or mouse. The header projects its result
    /// from the same active page; visiting the owning page restores controls.
    pub(crate) fn phase_result_target_phase(&self) -> Option<WorkflowPhase> {
        if self.shell_view() != ShellView::Workbench {
            return None;
        }
        let phase = crate::ui_view_models::active_workbench_page(self).phase();
        self.engagement.unresolved_phase_attempt(phase).map(|_| phase)
    }`);
edit(tui + 'app/state_transitions/key_dispatch.rs',
`        if self.input_mode() != InputMode::Navigate
            || !self.phase_result_is_open()
            || !key.modifiers.is_empty()`,
`        if self.input_mode() != InputMode::Navigate
            || !self.input().is_empty()
            || !self.phase_result_is_open()
            || !key.modifiers.is_empty()`);
edit(tui + 'app/state_transitions/key_dispatch.rs',
`        if self.input_mode() != InputMode::Navigate || !self.phase_result_is_open() {
            return None;
        }`,
`        if self.input_mode() != InputMode::Navigate
            || !self.input().is_empty()
            || !self.phase_result_is_open()
        {
            return None;
        }`);
append(tui + 'app/state_transitions/key_dispatch/phase_result_tests.rs', `

#[test]
fn off_page_result_never_owns_the_visible_pages_shortcuts() {
    for key in ['u', 'n', 'r', 'd', 'o'] {
        let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "context:build");
        fixture.app.router.workbench_mut().set_page(Some(WorkbenchPage::Review));
        assert_eq!(fixture.app.phase_result_target_phase(), None);
        assert!(crate::ui_view_models::phase_cockpit_model_for_phase(
            &fixture.app, WorkflowPhase::Review
        ).header.result_card.is_none());
        fixture.press(key);
        assert!(fixture.attempt_is_unresolved(WorkflowPhase::Map),
            "off-page Map attempt was changed by {key}");
        assert!(fixture.app.engagement.pending_phase_rerun().is_none());
    }
}

#[test]
fn returning_to_the_result_page_restores_its_advertised_action() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "context:build");
    fixture.app.router.workbench_mut().set_page(Some(WorkbenchPage::Review));
    assert_eq!(fixture.app.phase_result_target_phase(), None);
    fixture.app.router.workbench_mut().set_page(Some(WorkbenchPage::Map));
    assert_eq!(fixture.app.phase_result_target_phase(), Some(WorkflowPhase::Map));
    fixture.press('u');
    assert!(!fixture.attempt_is_unresolved(WorkflowPhase::Map));
}

#[test]
fn contextual_views_do_not_inherit_workbench_result_ownership() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "context:build");
    fixture.app.set_shell_view(ShellView::Report);
    assert_eq!(fixture.app.phase_result_target_phase(), None);
    assert!(fixture.attempt_is_unresolved(WorkflowPhase::Map));
}
`);
const prove = tui + 'ui_view_models/phase_cockpit/confirm.rs';
edit(prove, 'evidence_goals: investigation_evidence_goals(raw, proof),',
  'evidence_goals: investigation_evidence_goals(raw, proof, boundary),');
edit(prove, `fn investigation_evidence_goals(
    finding: &kuzushi_core::Finding,
    proof: Option<&ProofReplayModel>,
) -> Vec<String> {`, `fn investigation_evidence_goals(
    finding: &kuzushi_core::Finding,
    proof: Option<&ProofReplayModel>,
    boundary: crate::app::InvestigationBoundary,
) -> Vec<String> {`);
edit(prove, `    match (has_runtime_attempt, proof) {
        (false, _) => {
            goals.push("Attempt safe reproduction and record a runtime witness".to_string());
        }
        (true, Some(replay)) if replay.requires_revalidation => {
            goals.push("Re-validate the stale proof against the current observation".to_string());
        }
        _ => {}
    }`, `    if boundary == crate::app::InvestigationBoundary::LocalReproduction {
        append_runtime_investigation_goals(&mut goals, has_runtime_attempt, proof);
    }`);
edit(prove, '\nfn proof_replay_model(', `
/// Only an explicitly selected local-reproduction run can promise runtime work.
fn append_runtime_investigation_goals(
    goals: &mut Vec<String>,
    has_runtime_attempt: bool,
    proof: Option<&ProofReplayModel>,
) {
    match (has_runtime_attempt, proof) {
        (false, _) => goals.push("Attempt safe reproduction and record a runtime witness".to_string()),
        (true, Some(replay)) if replay.requires_revalidation => {
            goals.push("Re-validate the stale proof against the current observation".to_string());
        }
        _ => {}
    }
}

fn proof_replay_model(`);
for (const [call, count] of [
  ['investigation_evidence_goals(&bare_finding(), None)', 1],
  ['investigation_evidence_goals(&finding, Some(&replay(false)))', 2],
  ['investigation_evidence_goals(&finding, Some(&replay(true)))', 1],
]) {
  const text = staged.get(prove);
  assert.equal(text.split(call).length - 1, count, `goal test call count: ${call}`);
  staged.set(prove, text.replaceAll(call, call.slice(0, -1) + ', crate::app::InvestigationBoundary::LocalReproduction)'));
}
edit(prove, `    #[test]
    fn unproven_uncorroborated_finding_derives_every_gap_as_a_goal() {`, `    #[test]
    fn static_only_goals_never_promise_a_runtime_witness() {
        let goals = investigation_evidence_goals(
            &bare_finding(), None, crate::app::InvestigationBoundary::StaticOnly,
        );
        assert!(goals.iter().any(|goal| goal.contains("evidence anchors")));
        assert!(!goals.iter().any(|goal| goal.contains("runtime witness")));
        assert!(!goals.iter().any(|goal| goal.contains("safe reproduction")));
    }

    #[test]
    fn static_only_does_not_promise_to_refresh_stale_runtime_proof() {
        let mut finding = bare_finding();
        finding.verification = Some(crate::test_support::test_empirical_verification(3));
        let goals = investigation_evidence_goals(
            &finding, Some(&replay(true)), crate::app::InvestigationBoundary::StaticOnly,
        );
        assert!(!goals.iter().any(|goal| goal.contains("stale proof")));
    }

    #[test]
    fn unproven_uncorroborated_finding_derives_every_gap_as_a_goal() {`);
edit(tui + 'renderer/views/workbench/phase_pages/confirm.rs',
`    append_evidence_goals(&mut lines, plan, width);
    lines.push(Line::styled(fit("SAFETY BOUNDARY", width), theme::label()));`,
`    append_evidence_goals(&mut lines, plan, width);
    if !plan.empirical {
        lines.extend(crate::renderer::shared::text::wrap_text(
            "This static-only run will not produce or refresh a runtime witness.", width,
        ).into_iter().map(|text| Line::styled(text, theme::muted())));
    }
    lines.push(Line::styled(fit("SAFETY BOUNDARY", width), theme::label()));`);
const report = tui + 'renderer/views/report.rs';
edit(report, '&report_actions(route.receipt().is_some()),',
  '&report_actions(route.receipt().is_some(), route.receipt().is_some_and(|receipt| receipt.error.is_some())),');
edit(report, `fn report_actions(has_receipt: bool) -> [&'static str; 6] {
    if has_receipt {`, `fn report_actions(has_receipt: bool, failed: bool) -> [&'static str; 6] {
    if has_receipt && !failed {
        return [
            "j/k format", "c completeness", "e edit path",
            "Enter export again", "o Reveal Destination", "Esc Return",
        ];
    }
    if has_receipt {`);
edit(report, `            "Enter Retry",
            "o Reveal Destination",`, `            "Enter Retry",
            "o reveal after successful export",`);
append(report, `

#[cfg(test)]
mod export_action_tests {
    use super::report_actions;

    #[test]
    fn successful_export_is_not_presented_as_a_failure_to_retry() {
        let actions = report_actions(true, false);
        assert!(actions.contains(&"Enter export again"));
        assert!(actions.contains(&"o Reveal Destination"));
        assert!(!actions.contains(&"Enter Retry"));
    }

    #[test]
    fn failed_export_offers_retry_without_claiming_a_revealable_file() {
        let actions = report_actions(true, true);
        assert!(actions.contains(&"Enter Retry"));
        assert!(!actions.contains(&"o Reveal Destination"));
    }

    #[test]
    fn new_export_keeps_the_original_export_action() {
        assert!(report_actions(false, false).contains(&"Enter export"));
    }
}
`);
edit('scripts/verify-repository.mjs',
`  step("cargo-check", cargo, ["check", "--workspace", "--all-targets", "--locked"]),`,
`  step("cargo-check", cargo, ["check", "--workspace", "--all-targets", "--locked"]),
  step("tui-tests", cargo, ["test", "-p", "kuzushi-tui", "--lib", "--locked"]),`);
edit('scripts/verify-repository.test.mjs',
`  assert.ok(quick.includes("cargo-check"));`,
`  assert.ok(quick.includes("cargo-check"));
  assert.ok(quick.includes("tui-tests"));
  assert.deepEqual(stepArgs(quickPlan, "tui-tests"), [
    "test", "-p", "kuzushi-tui", "--lib", "--locked",
  ]);`);
for (const [path, text] of staged) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  console.log(path);
}
