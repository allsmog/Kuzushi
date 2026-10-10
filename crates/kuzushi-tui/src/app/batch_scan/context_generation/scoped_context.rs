use super::*;
use kuzushi_core::capabilities::campaign::ScopeStudyOriginV1;

impl ShellApp {
    pub(super) fn open_scope_context_generation(&mut self) -> bool {
        let Some(scope_id) = self
            .study_context_picker()
            .and_then(|picker| picker.scope_id.clone())
        else {
            return false;
        };
        match self.scope_context_generation_input(&scope_id) {
            Ok(input) => self.edit_context_picker(|config| {
                config.context_generation=Some(StudyContextGeneration {generation_tool:Some("threat-model:build".into()),context_input:input,..Default::default()});
                config.notice=Some("Review one inactive file-group context draft and its shared allowance. No model request or discovery jobs started.".into());
            }),
            Err(error) => self.set_batch_config_notice(format!("Cannot generate boundary context: {error:#}")),
        }
        true
    }

    fn scope_context_generation_input(&self, id: &str) -> Result<Value> {
        let config = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .context("Open the scope study first")?;
        let draft =
            config.study.scope_draft.as_ref().context(
                "Open accepted scopes and their study before generating a boundary draft",
            )?;
        anyhow::ensure!(
            draft.cases.iter().any(|case| case.scope_id == id),
            "The selected boundary is no longer in this draft"
        );
        let picker = self
            .study_context_picker()
            .context("Open boundary context first")?;
        Ok(
            json!({"scanScopeRef":{"proposal":draft.proposal_ref,"scopeId":id},"inheritedContextRef":picker.selected,
            "maxSourceBytes":65536,"contextLimit":200,"maxOutputTokens":8192}),
        )
    }

    pub(super) fn bind_scope_context_origin(
        &self,
        config: &BatchScanConfig,
        input: &mut Value,
    ) -> Result<()> {
        if !config
            .context_generation
            .as_ref()
            .is_some_and(StudyContextGeneration::is_scope_context)
        {
            return Ok(());
        }
        let Some(draft) = config.study.scope_draft.as_ref() else {
            return Ok(());
        };
        let scan_input = super::super::launch::configured_scan_input(self, config)?;
        input["scopeStudyOrigin"] = json!(ScopeStudyOriginV1 {
            schema_version: 1,
            scope_proposal_ref: draft.proposal_ref.clone(),
            scope_cases: draft.cases.clone(),
            scan_input,
            resource_baseline_campaign_id: config.prior_campaign_id.clone()
        });
        Ok(())
    }
}

pub(super) fn restore_origin(config: &mut BatchScanConfig, receipt: &ContextStudyReceipt) {
    let Some(origin) = &receipt.scope_study_origin else {
        return;
    };
    config.study.scope_draft = Some(origin.draft());
    config.study.scan_input = Some(origin.scan_input.clone());
    config.prior_campaign_id = origin.resource_baseline_campaign_id.clone();
    let selected = receipt
        .input
        .pointer("/scanScopeRef/scopeId")
        .and_then(Value::as_str);
    config.scope_context.open = true;
    config.scope_context.cursor = origin
        .scope_cases
        .iter()
        .position(|case| Some(case.scope_id.as_str()) == selected)
        .map_or(0, |index| index + 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restored_scope_origin_keeps_omission_common_input_and_selected_boundary() {
        let receipt:ContextStudyReceipt=serde_json::from_value(json!({"generationTool":"threat-model:build","campaignId":"group-one","investigationId":"shared-investigation","planSha256":"sha256:test","sourceIdentity":"owned-source","configSha256":"sha256:config","model":"openai-codex:gpt-5.5","input":{"scanScopeRef":{"scopeId":"app"}},
            "scopeStudyOrigin":{"schemaVersion":1,"scopeProposalRef":{"proposalId":"owned","revision":1,"recordHash":"a".repeat(64)},"scopeCases":[{"scopeId":"app","passes":3},{"scopeId":"other","passes":3,"threatModelRef":null}],"scanInput":{"threatModelRef":null,"tasks":["agentic"]}}})).unwrap();
        let mut config = BatchScanConfig::load(std::path::Path::new("/tmp/owned"), None);
        restore_origin(&mut config, &receipt);
        let draft = config.study.scope_draft.as_ref().unwrap();
        assert_eq!(draft.cases.len(), 2);
        assert_eq!(draft.cases[0].threat_model_ref, None);
        assert_eq!(draft.cases[1].threat_model_ref, Some(Value::Null));
        assert_eq!(
            config.study.scan_input.as_ref().unwrap()["tasks"],
            json!(["agentic"])
        );
        assert_eq!(config.scope_context.cursor, 1);
        assert!(config.scope_context.open);
    }
}
