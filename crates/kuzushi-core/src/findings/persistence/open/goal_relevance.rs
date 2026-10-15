use super::*;
use crate::findings::persistence::goal_reads;
use crate::findings::{FindingGoalAssessment, FindingGoalBasis};
use crate::storage_v3::writer_actor::{DecisionCommand, StorageWriterActor, WriterCommand};

impl FindingStore {
    pub(crate) fn goal_bases(
        &self,
        findings: &[Finding],
    ) -> Result<std::collections::BTreeMap<i64, FindingGoalBasis>> {
        goal_reads::bases(&self.conn, findings)
    }

    pub fn finding_goal_history(&self, finding_id: i64) -> Result<Vec<FindingGoalAssessment>> {
        goal_reads::history(&self.conn, finding_id)
    }

    pub(crate) fn goals_for_brief(
        &self,
        brief: &crate::capabilities::campaign::BriefReference,
    ) -> Result<Vec<FindingGoalAssessment>> {
        goal_reads::for_brief(&self.conn, brief)
    }

    pub(crate) fn save_goal_assessment(
        &self,
        record: &FindingGoalAssessment,
        expected_revision: u64,
    ) -> Result<()> {
        let (log, db) = self.required_v3_storage_paths("goal relevance")?;
        StorageWriterActor::commit_blocking(
            log,
            db,
            WriterCommand::Decision(DecisionCommand::FindingGoalAssessment {
                record: record.clone(),
                expected_revision,
            }),
        )?;
        Ok(())
    }
}
