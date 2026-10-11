//! Durable return draft. It grants no discovery jobs or spending authority.
use super::*;
use crate::capabilities::campaign::{ScopeStudyCaseInput, ScopeStudyDraft};
use crate::workspace::ScanScopeProposalRef;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeStudyOriginV1 {
    pub schema_version: u32,
    pub scope_proposal_ref: ScanScopeProposalRef,
    pub scope_cases: Vec<ScopeStudyCaseInput>,
    pub scan_input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_baseline_campaign_id: Option<String>,
}

impl ScopeStudyOriginV1 {
    pub fn draft(&self) -> ScopeStudyDraft {
        ScopeStudyDraft {
            proposal_ref: self.scope_proposal_ref.clone(),
            cases: self.scope_cases.clone(),
        }
    }
    fn validate(&self, generation_input: &Value) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1,
            "Unsupported scope study return draft version"
        );
        self.draft().validate()?;
        if let Some(id) = &self.resource_baseline_campaign_id {
            super::super::validate_scan_batch_id(id)?;
        }
        let scope: crate::workspace::ScanScopeRef =
            serde_json::from_value(generation_input["scanScopeRef"].clone())
                .context("A scope return draft requires accepted file-group generation")?;
        anyhow::ensure!(
            scope.proposal == self.scope_proposal_ref
                && self
                    .scope_cases
                    .iter()
                    .any(|case| case.scope_id == scope.scope_id),
            "Context generation does not match the return draft's selected boundary"
        );
        anyhow::ensure!(
            self.scan_input.get("threatModelRef").is_some(),
            "The scope return draft needs an exact common context reference or explicit omission"
        );
        anyhow::ensure!(
            self.scan_input.get("allowanceRef").is_none()
                && self.scan_input.get("scanScopeRef").is_none(),
            "Return drafts do not carry work approval or a single discovery binding"
        );
        Ok(())
    }
}

pub(super) fn attach(
    plan: &mut Value,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(value) = input.get("scopeStudyOrigin") else {
        return Ok(());
    };
    anyhow::ensure!(
        serde_json::to_vec(value)?.len() <= 256 * 1024,
        "Scope return draft exceeds 256 KiB"
    );
    let mut origin: ScopeStudyOriginV1 = serde_json::from_value(value.clone())?;
    let generation = &plan["jobs"].as_array().unwrap().last().unwrap()["input"];
    origin.validate(generation)?;
    let review =
        crate::workspace::load_accepted_scan_scope_proposal(ctx, &origin.scope_proposal_ref)?;
    for case in &origin.scope_cases {
        anyhow::ensure!(
            review
                .coverage
                .discovery_members
                .get(&case.scope_id)
                .is_some_and(|members| members.total > 0),
            "Return draft contains an unavailable discovery boundary"
        );
    }
    origin.scan_input = ModuleRegistry::with_v2_builtins()
        .prepare_dispatch_input("sast:scan", origin.scan_input.clone(), ctx, None)?
        .value()
        .clone();
    plan["scopeStudyOrigin"] = serde_json::to_value(origin)?;
    Ok(())
}

pub(super) fn read(plan: &Value, generation_input: &Value) -> Result<Option<ScopeStudyOriginV1>> {
    let Some(value) = plan.get("scopeStudyOrigin") else {
        return Ok(None);
    };
    let origin: ScopeStudyOriginV1 = serde_json::from_value(value.clone())?;
    origin.validate(generation_input)?;
    Ok(Some(origin))
}
