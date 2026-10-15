//! Retain every authenticated attempt's observations without assigning recurrence.
use super::*;

pub(super) fn load_observations(
    root: &Path,
    store: &FindingStore,
    trials: &[BatchTrialReport],
) -> Result<BTreeMap<String, Vec<Finding>>> {
    let parents = trials
        .iter()
        .flat_map(|trial| trial.attempt_run_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let runs = super::super::load::observation_run_refs(root, &parents)?;
    runs.into_iter()
        .map(|run| {
            let findings = store.list_findings_for_scan_id(&run)?;
            Ok((run, findings))
        })
        .collect()
}
