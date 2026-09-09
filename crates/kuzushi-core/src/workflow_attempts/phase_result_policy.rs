use super::{PhaseAttemptDisposition, PhaseAttemptEvent, PhaseAttemptLedger};
use anyhow::Result;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

pub(super) fn ensure_phase_result_refs(target: &Path, run_refs: &[String]) -> Result<()> {
    anyhow::ensure!(
        !only_non_phase_results(target, run_refs),
        "These tools produce supporting evidence, not a selectable phase result"
    );
    Ok(())
}

pub(super) fn ensure_event_is_phase_result(
    target: &Path,
    event: &PhaseAttemptEvent,
    history: &[PhaseAttemptEvent],
) -> Result<()> {
    match event {
        PhaseAttemptEvent::PhaseAttemptCompleted(completed) => {
            ensure_phase_result_refs(target, &completed.run_refs)
        }
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(disposition) => {
            ensure_selection(target, disposition, history)
        }
        _ => Ok(()),
    }
}

fn ensure_selection(
    target: &Path,
    disposition: &super::PhaseAttemptDispositionRecorded,
    history: &[PhaseAttemptEvent],
) -> Result<()> {
    if !matches!(
        disposition.disposition,
        PhaseAttemptDisposition::Selected { .. }
    ) {
        return Ok(());
    }
    let completed = completed_attempt_for(history, &disposition.attempt_id);
    match completed {
        Some(completed) => ensure_phase_result_refs(target, &completed.run_refs),
        None => Ok(()), // The ledger's identity validation reports missing attempts.
    }
}

fn completed_attempt_for<'a>(
    history: &'a [PhaseAttemptEvent],
    attempt_id: &str,
) -> Option<&'a super::PhaseAttemptCompleted> {
    history.iter().find_map(|event| match event {
        PhaseAttemptEvent::PhaseAttemptCompleted(completed)
            if completed.attempt_id == attempt_id =>
        {
            Some(completed)
        }
        _ => None,
    })
}

pub(super) fn exclude_non_phase_results(target: &Path, ledger: &mut PhaseAttemptLedger) {
    let excluded = ledger
        .attempts()
        .filter(|attempt| only_non_phase_results(target, &attempt.completed.run_refs))
        .map(|attempt| attempt.completed.attempt_id.clone())
        .collect();
    ledger.exclude_from_phase_projection(&excluded);
}

fn only_non_phase_results(target: &Path, run_refs: &[String]) -> bool {
    !run_refs.is_empty()
        && run_refs
            .iter()
            .all(|run_id| non_phase_result_run(target, run_id))
}

fn non_phase_result_run(target: &Path, run_id: &str) -> bool {
    crate::run_artifacts::load_run_summary(target, run_id)
        .ok()
        .and_then(|summary| summary.tool)
        .is_some_and(|tool| non_phase_result_tools().contains(&tool))
}

/// Built-in policy is stable for the process. Unknown historical tools retain
/// their existing validation and visibility instead of being silently removed.
fn non_phase_result_tools() -> &'static BTreeSet<String> {
    static TOOLS: OnceLock<BTreeSet<String>> = OnceLock::new();
    TOOLS.get_or_init(|| {
        crate::modules::ModuleRegistry::with_v2_builtins()
            .all_modules()
            .flat_map(|module| module.tools())
            .filter(|tool| !tool.phase_result)
            .map(|tool| tool.name.clone())
            .collect()
    })
}
