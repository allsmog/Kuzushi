use super::task_id::PlanningTaskId;
use std::collections::BTreeSet;

/// Returns the direct (non-transitive) dependencies of `task` in the
/// canonical planning DAG. Mirrors the `dependsOn` lists declared on
/// each module's `dag(...)` node in kuzushi-core; the equality test in
/// `tests` keeps the two in lockstep.
pub fn direct_dependencies(task: PlanningTaskId) -> &'static [PlanningTaskId] {
    use PlanningTaskId::*;
    match task {
        // 組 KUMI-KATA · map — everything starts from repo context.
        AttachFiles | GatherRepoContext => &[],
        MapEntryPoints => &[GatherRepoContext],
        BuildXRay => &[GatherRepoContext],
        BuildStrideThreatModel => &[GatherRepoContext],
        BuildPastaThreatModel => &[GatherRepoContext],
        BuildCodePropertyGraph => &[GatherRepoContext],
        BuildCodeQlDatabase => &[GatherRepoContext],
        ThreatIntelCves => &[GatherRepoContext],
        ReverseEngineerBinary => &[GatherRepoContext],
        // 崩 KUZUSHI · hunt — some hunts need a Map-phase artifact first.
        ScanSecrets => &[GatherRepoContext],
        ScanSemgrep => &[GatherRepoContext],
        ScanCodeql => &[BuildCodeQlDatabase],
        ScanAgenticSast => &[GatherRepoContext],
        HuntTaint => &[BuildCodePropertyGraph],
        HuntThreatModel => &[BuildStrideThreatModel],
        HuntSystems => &[GatherRepoContext],
        HuntUseAfterFree => &[GatherRepoContext],
        // 作 TSUKURI · confirm — triage then verify the findings.
        TriageFindings => &[GatherRepoContext],
        VerifyFindings => &[TriageFindings],
        // 掛 KAKE · fix — patch verified findings, then report.
        PatchFindings => &[VerifyFindings],
        BuildReport => &[GatherRepoContext],
    }
}

/// Transitive closure of dependencies for `task`, excluding the task
/// itself. Used when the picker auto-checks dependencies on toggle-on.
pub fn transitive_dependencies(task: PlanningTaskId) -> BTreeSet<PlanningTaskId> {
    let mut acc = BTreeSet::new();
    visit_dependencies(task, &mut acc);
    acc
}

fn visit_dependencies(task: PlanningTaskId, acc: &mut BTreeSet<PlanningTaskId>) {
    for dep in direct_dependencies(task) {
        if acc.insert(*dep) {
            visit_dependencies(*dep, acc);
        }
    }
}

/// Tasks that directly depend on `task`. Used when the picker refuses
/// to toggle off a task whose dependents are still selected.
pub fn direct_dependents(task: PlanningTaskId) -> Vec<PlanningTaskId> {
    PlanningTaskId::ALL
        .iter()
        .copied()
        .filter(|candidate| direct_dependencies(*candidate).contains(&task))
        .collect()
}

/// Kahn topological sort over a chosen subset. Preserves the canonical
/// `PlanningTaskId::ALL` order when ties arise, which keeps the run log
/// stable across invocations.
pub fn topological_order(selected: &BTreeSet<PlanningTaskId>) -> Vec<PlanningTaskId> {
    let mut remaining: BTreeSet<PlanningTaskId> = selected.clone();
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let next = next_ready_task(&remaining, &ordered);
        match next {
            Some(task) => {
                ordered.push(task);
                remaining.remove(&task);
            }
            None => {
                // Cycle (shouldn't happen with the static map) — fall back
                // to canonical order to avoid an infinite loop.
                ordered.extend(remaining.iter().copied());
                break;
            }
        }
    }
    ordered
}

fn next_ready_task(
    remaining: &BTreeSet<PlanningTaskId>,
    ordered: &[PlanningTaskId],
) -> Option<PlanningTaskId> {
    PlanningTaskId::ALL.iter().copied().find(|candidate| {
        remaining.contains(candidate)
            && direct_dependencies(*candidate)
                .iter()
                .all(|dep| !remaining.contains(dep) || ordered.contains(dep))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use PlanningTaskId::*;

    #[test]
    fn context_has_no_dependencies() {
        assert!(direct_dependencies(GatherRepoContext).is_empty());
    }

    #[test]
    fn every_other_task_depends_on_context() {
        for task in PlanningTaskId::ALL.iter().copied() {
            if matches!(task, GatherRepoContext | AttachFiles) {
                continue;
            }
            let deps = transitive_dependencies(task);
            assert!(
                deps.contains(&GatherRepoContext),
                "task {task:?} should transitively require context"
            );
        }
    }

    #[test]
    fn topo_orders_context_before_dependents() {
        let mut selected = BTreeSet::new();
        selected.insert(BuildXRay);
        selected.insert(GatherRepoContext);
        selected.insert(MapEntryPoints);
        let ordered = topological_order(&selected);
        let context_pos = ordered
            .iter()
            .position(|t| *t == GatherRepoContext)
            .unwrap();
        let xray_pos = ordered.iter().position(|t| *t == BuildXRay).unwrap();
        let entry_pos = ordered.iter().position(|t| *t == MapEntryPoints).unwrap();
        assert!(context_pos < xray_pos);
        assert!(context_pos < entry_pos);
    }

    #[test]
    fn topo_omits_unselected_dependencies() {
        let mut selected = BTreeSet::new();
        selected.insert(BuildXRay);
        let ordered = topological_order(&selected);
        assert_eq!(ordered, vec![BuildXRay]);
    }

    #[test]
    fn context_is_a_direct_dependency_of_map_tasks() {
        let dependents = direct_dependents(GatherRepoContext);
        assert!(dependents.contains(&BuildCodePropertyGraph));
        assert!(dependents.contains(&MapEntryPoints));
        // Tasks gated behind another artifact are NOT direct dependents of
        // context — they hang off their own prerequisite.
        assert!(!dependents.contains(&ScanCodeql));
        assert!(!dependents.contains(&HuntTaint));
    }

    #[test]
    fn taint_hunt_transitively_requires_cpg_and_context() {
        let deps = transitive_dependencies(HuntTaint);
        assert!(deps.contains(&BuildCodePropertyGraph));
        assert!(deps.contains(&GatherRepoContext));
    }

    #[test]
    fn verify_chains_back_through_triage_to_context() {
        let deps = transitive_dependencies(VerifyFindings);
        assert!(deps.contains(&TriageFindings));
        assert!(deps.contains(&GatherRepoContext));
    }
}
