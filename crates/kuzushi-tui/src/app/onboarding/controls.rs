use super::dependencies::{direct_dependents, topological_order, transitive_dependencies};
use super::task_id::PlanningTaskId;
use super::task_row::PlanningTaskRow;
use std::collections::BTreeSet;

/// Outcome of toggling a row in the planning picker. Reported back to
/// the caller (the key handler) so it can emit log lines without
/// having to know the dependency logic itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToggleOutcome {
    /// Row toggled on. `auto_added` lists transitively-included
    /// dependencies that were auto-checked at the same time.
    On {
        task: PlanningTaskId,
        auto_added: Vec<PlanningTaskId>,
    },
    /// Row toggled off cleanly (no dependents were still selected).
    Off { task: PlanningTaskId },
    /// Refused to toggle off because dependents are still selected.
    Blocked {
        task: PlanningTaskId,
        dependents: Vec<PlanningTaskId>,
    },
    /// Tried to toggle a row whose CLI requirement isn't met
    /// (joern-parse / codeql not on PATH).
    MissingCli {
        task: PlanningTaskId,
        cli: &'static str,
    },
}

pub fn toggle_planning_row(
    task: PlanningTaskId,
    rows: &[PlanningTaskRow],
    selected: &mut BTreeSet<PlanningTaskId>,
) -> ToggleOutcome {
    let row = match rows.iter().find(|row| row.id == task) {
        Some(row) => row,
        None => return ToggleOutcome::Off { task },
    };
    if !row.cli_available {
        return ToggleOutcome::MissingCli {
            task,
            cli: row.required_cli.unwrap_or("required binary"),
        };
    }
    if selected.contains(&task) {
        toggle_off(task, selected)
    } else {
        toggle_on(task, selected)
    }
}

fn toggle_on(task: PlanningTaskId, selected: &mut BTreeSet<PlanningTaskId>) -> ToggleOutcome {
    let mut auto_added = Vec::new();
    for dep in transitive_dependencies(task) {
        if selected.insert(dep) {
            auto_added.push(dep);
        }
    }
    selected.insert(task);
    ToggleOutcome::On { task, auto_added }
}

fn toggle_off(task: PlanningTaskId, selected: &mut BTreeSet<PlanningTaskId>) -> ToggleOutcome {
    let still_needed: Vec<PlanningTaskId> = direct_dependents(task)
        .into_iter()
        .filter(|dep| selected.contains(dep))
        .collect();
    if !still_needed.is_empty() {
        return ToggleOutcome::Blocked {
            task,
            dependents: still_needed,
        };
    }
    selected.remove(&task);
    ToggleOutcome::Off { task }
}

/// What confirming the picker will actually do with a row. The checkbox glyph
/// renders from this, so `[x]` can never mean both "will run" and "cached,
/// reused without running" at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowDisposition {
    /// Checked and runnable: Enter includes it in the execution plan.
    WillRun,
    /// Checked but its cached artifact is reused — Enter does NOT run it
    /// (press `g` to rebuild).
    Reused,
    /// Unchecked: not part of this phase's plan.
    Off,
    /// Required CLI missing: cannot run regardless of selection.
    Unavailable,
}

pub fn row_disposition(
    row: &PlanningTaskRow,
    selected: &BTreeSet<PlanningTaskId>,
    rebuild: &BTreeSet<PlanningTaskId>,
) -> RowDisposition {
    if !row.cli_available {
        return RowDisposition::Unavailable;
    }
    if !selected.contains(&row.id) {
        return RowDisposition::Off;
    }
    if is_cached(row) && !rebuild.contains(&row.id) {
        return RowDisposition::Reused;
    }
    RowDisposition::WillRun
}

/// Build the ordered execution plan from the currently-selected rows. Cached
/// artifacts are reused (filtered out) unless the operator marked them for
/// rebuild — those are kept so they re-run and overwrite the stale artifact.
pub fn build_execution_plan(
    rows: &[PlanningTaskRow],
    selected: &BTreeSet<PlanningTaskId>,
    rebuild: &BTreeSet<PlanningTaskId>,
) -> Vec<PlanningTaskId> {
    let runnable: BTreeSet<PlanningTaskId> = selected
        .iter()
        .copied()
        .filter(|task| {
            rows.iter()
                .find(|row| row.id == *task)
                .map(|row| row.cli_available && (!is_cached(row) || rebuild.contains(task)))
                .unwrap_or(false)
        })
        .collect();
    topological_order(&runnable)
}

fn is_cached(row: &PlanningTaskRow) -> bool {
    matches!(row.artifact_state, super::task_row::ArtifactState::Cached)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::onboarding::task_row::ArtifactState;
    use std::path::PathBuf;
    use PlanningTaskId::*;

    fn row(id: PlanningTaskId, state: ArtifactState) -> PlanningTaskRow {
        PlanningTaskRow {
            id,
            label: id.label(),
            tool_name: id.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state: state,
            artifact_modified: None,
            model_backed: id.is_model_backed(),
            required_cli: id.required_cli(),
            cli_available: id.required_cli().is_none(),
        }
    }

    #[test]
    fn toggle_on_auto_adds_context() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Missing),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        let outcome = toggle_planning_row(BuildXRay, &rows, &mut selected);
        match outcome {
            ToggleOutcome::On { task, auto_added } => {
                assert_eq!(task, BuildXRay);
                assert_eq!(auto_added, vec![GatherRepoContext]);
            }
            other => panic!("expected On, got {other:?}"),
        }
        assert!(selected.contains(&GatherRepoContext));
        assert!(selected.contains(&BuildXRay));
    }

    #[test]
    fn toggle_off_blocked_when_dependents_present() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Missing),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        selected.insert(BuildXRay);
        let outcome = toggle_planning_row(GatherRepoContext, &rows, &mut selected);
        match outcome {
            ToggleOutcome::Blocked { task, dependents } => {
                assert_eq!(task, GatherRepoContext);
                assert_eq!(dependents, vec![BuildXRay]);
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert!(selected.contains(&GatherRepoContext));
    }

    #[test]
    fn toggle_off_succeeds_after_dependents_removed() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Missing),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        let outcome = toggle_planning_row(GatherRepoContext, &rows, &mut selected);
        assert_eq!(
            outcome,
            ToggleOutcome::Off {
                task: GatherRepoContext
            }
        );
        assert!(selected.is_empty());
    }

    #[test]
    fn execution_plan_skips_cached_rows() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Cached),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        selected.insert(BuildXRay);
        let plan = build_execution_plan(&rows, &selected, &BTreeSet::new());
        assert_eq!(plan, vec![BuildXRay]);
    }

    #[test]
    fn execution_plan_reruns_cached_rows_marked_for_rebuild() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Cached),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        selected.insert(BuildXRay);
        let mut rebuild = BTreeSet::new();
        rebuild.insert(GatherRepoContext);
        let plan = build_execution_plan(&rows, &selected, &rebuild);
        // context is cached but explicitly rebuilt, so it runs before its dependent.
        assert_eq!(plan, vec![GatherRepoContext, BuildXRay]);
    }

    #[test]
    fn disposition_separates_will_run_from_reused() {
        // The seed disconnect: a checked cached row used to look identical to a
        // row that will actually run. The disposition keeps the two states
        // distinct so the picker can label one RUN and the other REUSE.
        let cached = row(GatherRepoContext, ArtifactState::Cached);
        let missing = row(BuildXRay, ArtifactState::Missing);
        let selected: BTreeSet<PlanningTaskId> =
            [GatherRepoContext, BuildXRay].into_iter().collect();
        let rebuild = BTreeSet::new();
        assert_eq!(
            row_disposition(&cached, &selected, &rebuild),
            RowDisposition::Reused
        );
        assert_eq!(
            row_disposition(&missing, &selected, &rebuild),
            RowDisposition::WillRun
        );
    }

    #[test]
    fn disposition_promotes_rebuilt_cached_rows_to_will_run() {
        let cached = row(GatherRepoContext, ArtifactState::Cached);
        let selected: BTreeSet<PlanningTaskId> = [GatherRepoContext].into_iter().collect();
        let rebuild: BTreeSet<PlanningTaskId> = [GatherRepoContext].into_iter().collect();
        assert_eq!(
            row_disposition(&cached, &selected, &rebuild),
            RowDisposition::WillRun
        );
    }

    #[test]
    fn disposition_marks_unselected_and_unavailable_rows_off() {
        let unselected = row(GatherRepoContext, ArtifactState::Missing);
        let mut no_cli = row(BuildCodePropertyGraph, ArtifactState::Missing);
        no_cli.cli_available = false;
        let selected = BTreeSet::new();
        let rebuild = BTreeSet::new();
        assert_eq!(
            row_disposition(&unselected, &selected, &rebuild),
            RowDisposition::Off
        );
        assert_eq!(
            row_disposition(&no_cli, &selected, &rebuild),
            RowDisposition::Unavailable
        );
    }

    #[test]
    fn cpg_with_missing_cli_is_blocked() {
        // CPG row without joern-parse on PATH cannot be toggled on.
        let rows = vec![PlanningTaskRow {
            id: BuildCodePropertyGraph,
            label: BuildCodePropertyGraph.label(),
            tool_name: BuildCodePropertyGraph.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state: ArtifactState::Missing,
            artifact_modified: None,
            model_backed: false,
            required_cli: Some("joern-parse"),
            cli_available: false,
        }];
        let mut selected = BTreeSet::new();
        let outcome = toggle_planning_row(BuildCodePropertyGraph, &rows, &mut selected);
        assert_eq!(
            outcome,
            ToggleOutcome::MissingCli {
                task: BuildCodePropertyGraph,
                cli: "joern-parse"
            }
        );
        assert!(selected.is_empty());
    }
}
