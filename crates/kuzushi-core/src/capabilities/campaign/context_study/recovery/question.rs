use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContextQuestionAnswer {
    pub question: String,
    pub answer: String,
    pub context_ref: ThreatModelRef,
    pub model: String,
    pub run_id: String,
    pub source_identity: String,
    pub partial: bool,
}

impl ContextStudyReceipt {
    pub fn question_answer(&self, root: &Path) -> Result<Option<ContextQuestionAnswer>> {
        anyhow::ensure!(
            self.generation_tool == generation::QUESTION_TOOL,
            "This job does not answer a context question"
        );
        let snapshot =
            super::super::super::snapshot::load_campaign_snapshot(root, &self.campaign_id)?;
        let job = snapshot
            .jobs
            .iter()
            .find(|job| job.job_id == JOB)
            .context("Question study has no question job")?;
        anyhow::ensure!(
            job.tool.as_deref() == Some(generation::QUESTION_TOOL),
            "Question job tool changed"
        );
        if matches!(job.state.as_str(), "planned" | "running") {
            return Ok(None);
        }
        anyhow::ensure!(
            matches!(job.state.as_str(), "completed" | "partial"),
            "Question job is {}; inspect its run receipt",
            job.state
        );
        let run = job
            .run_id
            .as_deref()
            .context("Question job has no run receipt")?;
        load_answer(root, self, run).map(Some)
    }
}

fn load_answer(
    root: &Path,
    receipt: &ContextStudyReceipt,
    run: &str,
) -> Result<ContextQuestionAnswer> {
    let (_, body) =
        crate::run_artifacts::read_run_artifact_text_bounded(root, run, "result.json", 512 * 1024)?;
    let output: Value = serde_json::from_str(&body)?;
    anyhow::ensure!(
        matches!(output["status"].as_str(), Some("completed" | "partial")),
        "Question result is not a completed or partial answer; inspect its run receipt"
    );
    let data = &output["data"];
    anyhow::ensure!(
        data["schemaVersion"] == 1 && data["model"] == receipt.model,
        "Question result schema or model differs from the approved plan"
    );
    anyhow::ensure!(
        data["question"] == receipt.input["question"]
            && data["contextRef"] == receipt.input["threatModelRef"],
        "Question result does not match its frozen question and context"
    );
    let answer = data["answer"]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .context("Question result has no answer text")?;
    Ok(ContextQuestionAnswer {
        question: data["question"]
            .as_str()
            .context("Question text is missing")?
            .into(),
        answer: answer.into(),
        context_ref: serde_json::from_value(data["contextRef"].clone())?,
        model: receipt.model.clone(),
        run_id: run.into(),
        source_identity: receipt.source_identity.clone(),
        partial: output["status"] == "partial" || data["answerPartial"] == true,
    })
}
