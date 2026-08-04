use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use super::census_counting::{count_decisions, count_row_diversity};
use super::label_selection::{
    policy_transition_count, select_identity_label, IdentityOutcome, LabelSelection,
};
use super::row_assembly::{build_row, RowInputs};
use crate::review_yield::domain::{
    is_human_author, repository_group, CensusReport, TrainingExampleV1,
};
use crate::review_yield::persistence::{
    read_event_log_head, DecisionRow, ObservationMeta, ReviewYieldProjectionReader,
};
use crate::workspace::WorkspaceTarget;

pub struct DatasetBuild {
    pub rows: Vec<TrainingExampleV1>,
    pub census: CensusReport,
}

/// Single shared core for both the census and the export: the census is this
/// build with the rows discarded, so the two can never disagree.
pub fn build_review_yield_dataset(
    reader: &ReviewYieldProjectionReader,
    workspace: &WorkspaceTarget,
) -> Result<DatasetBuild> {
    let decisions = reader.all_decisions()?;
    let mut assembler = DatasetAssembler::new(reader, workspace, &decisions)?;
    for (identity_id, identity_decisions) in group_human_decisions(&decisions) {
        assembler.absorb_identity(&identity_id, &identity_decisions)?;
    }
    assembler.finish(workspace)
}

struct DatasetAssembler<'a> {
    reader: &'a ReviewYieldProjectionReader,
    repository_group: String,
    observations: BTreeMap<String, Vec<ObservationMeta>>,
    census: CensusReport,
    rows: Vec<TrainingExampleV1>,
}

impl<'a> DatasetAssembler<'a> {
    fn new(
        reader: &'a ReviewYieldProjectionReader,
        workspace: &WorkspaceTarget,
        decisions: &[DecisionRow],
    ) -> Result<Self> {
        let mut census = CensusReport::default();
        count_decisions(&mut census, decisions);
        Ok(Self {
            reader,
            repository_group: repository_group_for(reader, workspace)?,
            observations: reader.observation_index()?,
            census,
            rows: Vec::new(),
        })
    }

    fn absorb_identity(&mut self, identity_id: &str, decisions: &[&DecisionRow]) -> Result<()> {
        self.census.adjudicated_identities += 1;
        self.census.policy_transitions += policy_transition_count(decisions);
        let Some(selection) = self.record_outcome(select_identity_label(decisions)) else {
            return Ok(());
        };
        let observations = self.observations.get(identity_id).cloned().unwrap_or_default();
        let row = build_row(
            self.reader,
            RowInputs {
                identity_id,
                repository_group: &self.repository_group,
                selection: &selection,
                observations: &observations,
            },
        )?;
        self.push_row(row, &selection);
        Ok(())
    }

    fn record_outcome(&mut self, outcome: IdentityOutcome) -> Option<LabelSelection> {
        match outcome {
            IdentityOutcome::Labeled(selection) => Some(*selection),
            IdentityOutcome::Conflicted => count_only(&mut self.census.conflicted),
            IdentityOutcome::MissingExactCutoff => {
                count_only(&mut self.census.missing_exact_cutoff)
            }
            IdentityOutcome::NoEligibleLabel => count_only(&mut self.census.no_eligible_label),
        }
    }

    fn push_row(&mut self, row: Option<TrainingExampleV1>, selection: &LabelSelection) {
        let Some(row) = row else {
            self.census.missing_pre_cutoff_observation += 1;
            return;
        };
        self.census.eligible_identities += 1;
        self.census.positive += u64::from(selection.class == 1);
        self.census.negative += u64::from(selection.class == 0);
        self.rows.push(row);
    }

    fn finish(mut self, workspace: &WorkspaceTarget) -> Result<DatasetBuild> {
        self.rows
            .sort_by(|left, right| left.example_id.cmp(&right.example_id));
        ensure_one_row_per_identity(&self.rows)?;
        let meta = self.reader.projection_meta()?;
        self.census.distinct_repositories = self.reader.distinct_repository_count()?;
        self.census.projection_applied_seq = meta.applied_seq;
        self.census.projection_generation = meta.generation;
        self.census.event_log_head_seq = read_event_log_head(workspace)?.seq;
        count_row_diversity(&mut self.census, &self.rows);
        Ok(DatasetBuild {
            rows: self.rows,
            census: self.census,
        })
    }
}

fn count_only(counter: &mut u64) -> Option<LabelSelection> {
    *counter += 1;
    None
}

/// Human decisions that carry a durable identity, grouped by it and kept in
/// decision-event order.
fn group_human_decisions(decisions: &[DecisionRow]) -> BTreeMap<String, Vec<&DecisionRow>> {
    let mut groups: BTreeMap<String, Vec<&DecisionRow>> = BTreeMap::new();
    let human = decisions
        .iter()
        .filter(|decision| is_human_author(&decision.author));
    for decision in human {
        for identity_id in decision.identity_id.iter() {
            groups.entry(identity_id.clone()).or_default().push(decision);
        }
    }
    groups
}

fn ensure_one_row_per_identity(rows: &[TrainingExampleV1]) -> Result<()> {
    let groups: BTreeSet<&str> = rows.iter().map(|row| row.identity_group.as_str()).collect();
    anyhow::ensure!(
        groups.len() == rows.len(),
        "review-yield export produced {} rows for {} durable identities",
        rows.len(),
        groups.len()
    );
    Ok(())
}

/// The repository grouping key. Falls back to hashing the target root only
/// when no snapshot has been recorded yet; the raw fingerprint is never
/// exported because it hashes a local absolute path.
fn repository_group_for(
    reader: &ReviewYieldProjectionReader,
    workspace: &WorkspaceTarget,
) -> Result<String> {
    let fingerprint = reader.latest_workspace_root_fingerprint()?.unwrap_or_else(|| {
        crate::incremental_index::workspace_root_fingerprint(workspace.root())
    });
    Ok(repository_group(&fingerprint))
}
