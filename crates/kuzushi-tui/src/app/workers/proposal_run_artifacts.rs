use super::{PlanChange, PlanProposal, ThreatPatch};
use anyhow::{Context, Result};
use kuzushi_core::run_artifacts::ToolRunRecord;
use kuzushi_core::{V2Config, WorkflowPhase};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) struct ProposalRunMetadata {
    pub(crate) run_id: String,
    pub(crate) loaded_modules: Vec<String>,
}

pub(super) struct ProposalRun<'a> {
    pub target: &'a Path,
    pub run_id: &'a str,
    pub kind: &'a str,
    pub tool: &'a str,
}

impl ProposalRun<'_> {
    fn record(&self) -> ToolRunRecord<'_> {
        ToolRunRecord::new(self.target, self.run_id, self.kind, self.tool)
    }

    pub(super) fn start(
        &self,
        input: &Value,
        model: String,
        config: &V2Config,
        loaded_modules: Vec<String>,
    ) -> Result<()> {
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            self.record(),
            input,
            Some(model),
            kuzushi_core::config_hash(config).ok(),
            loaded_modules,
        )
        .context("could not persist the proposal run before model execution")
    }

    pub(super) fn complete(
        &self,
        summary: &str,
        proposal: Value,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) -> Result<()> {
        let result = completed_result(summary, proposal, cost);
        kuzushi_core::run_artifacts::try_record_tool_run_complete(self.record(), &result)
            .context("could not persist the proposal result")
    }

    pub(super) fn fail(&self, error: &str, canceled: bool) -> Result<()> {
        if canceled {
            kuzushi_core::run_artifacts::try_record_tool_run_canceled(self.record(), error)
        } else {
            kuzushi_core::run_artifacts::try_record_tool_run_failed(self.record(), error)
        }
    }
}

pub(super) fn planner_input(goal: &str, phase: Option<WorkflowPhase>) -> Value {
    json!({
        "goal": goal,
        "phaseIntent": phase,
    })
}

pub(super) fn planner_proposal_value(plan: &PlanProposal) -> Value {
    json!({
        "goal": plan.goal,
        "summary": plan.summary,
        "changes": plan.changes.iter().map(plan_change_value).collect::<Vec<_>>(),
        "unsupported": plan.unsupported,
    })
}

pub(super) fn threat_regen_input(existing: &Value) -> Value {
    json!({
        "action": "regenerate",
        "existingThreatModel": existing,
    })
}

pub(super) fn threat_ask_input(existing: &Value, question: &str) -> Value {
    json!({
        "action": "ask",
        "question": question,
        "existingThreatModel": existing,
    })
}

pub(super) fn threat_patch_value(patch: &ThreatPatch) -> Value {
    json!({
        "goal": patch.goal,
        "summary": patch.summary,
        "patch": patch.patch,
        "unsupported": patch.unsupported,
    })
}

fn plan_change_value(change: &PlanChange) -> Value {
    match change {
        PlanChange::RunTool { phase, tool, input } => json!({
            "kind": "run_tool",
            "phase": phase,
            "tool": tool,
            "input": input,
        }),
        PlanChange::SetOption {
            phase,
            global,
            tool,
            name,
            value,
        } => json!({
            "kind": "set_option",
            "phase": phase,
            "global": global,
            "tool": tool,
            "name": name,
            "value": value,
        }),
        PlanChange::Ask { question } => json!({ "kind": "ask", "question": question }),
        PlanChange::Note { text } => json!({ "kind": "note", "text": text }),
    }
}

fn completed_result(
    summary: &str,
    proposal: Value,
    cost: kuzushi_core::runtime::RuntimeCostReport,
) -> Value {
    let observed = (!cost.is_complete() && !cost.is_unavailable()).then(|| cost.observed_usd());
    json!({
        "ok": true,
        "status": "completed",
        "summary": summary,
        "output": summary,
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "costUsd": cost.exact_usd(),
        "observedCostUsd": observed,
        "providerSpendUnresolved": observed.is_some(),
        "data": { "proposal": proposal },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_runs_persist_canonical_input_result_and_summary() {
        let temp = tempfile::tempdir().unwrap();
        let run = ProposalRun {
            target: temp.path(),
            run_id: "plan-restart-safe",
            kind: "plan",
            tool: "planner:propose",
        };
        let input = planner_input("scan auth", Some(WorkflowPhase::Scan));
        run.start(
            &input,
            "openai:test".to_string(),
            &V2Config::default(),
            vec!["builtin:test".to_string()],
        )
        .unwrap();
        run.complete(
            "proposal ready",
            json!({ "summary": "scan auth" }),
            kuzushi_core::runtime::RuntimeCostReport::known(
                kuzushi_core::runtime::RuntimeCost::ZERO,
            ),
        )
        .unwrap();

        let persisted_input = persisted_json(temp.path(), run.run_id, "input.json");
        let persisted_result = persisted_json(temp.path(), run.run_id, "result.json");
        let summary = kuzushi_core::load_run_summary(temp.path(), run.run_id).unwrap();
        assert_eq!(persisted_input["phaseIntent"], "scan");
        assert_eq!(persisted_result["data"]["proposal"]["summary"], "scan auth");
        assert_eq!(summary.status, "completed");
        assert_eq!(summary.tool.as_deref(), Some("planner:propose"));
    }

    fn persisted_json(target: &Path, run_id: &str, leaf: &str) -> Value {
        let (_, body) = kuzushi_core::read_run_artifact_text(target, run_id, leaf)
            .require("proposal run artifact")
            .unwrap();
        serde_json::from_str(&body).unwrap()
    }
}
