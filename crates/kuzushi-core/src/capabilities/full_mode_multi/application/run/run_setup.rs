use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::capabilities::full_mode_multi::application::chunk_prompt::{
    SYSTEM_PROMPT_C, SYSTEM_PROMPT_UNKNOWN,
};
use crate::capabilities::full_mode_multi::domain::{
    FullModeLanguage, FullModePlan, FullModeReport,
};
use anyhow::{Context, Result};

pub(super) fn dry_run_report(plan: FullModePlan) -> FullModeReport {
    FullModeReport {
        findings: Vec::new(),
        plan,
        chunks_dispatched: 0,
        chunks_failed: 0,
        failed_chunk_errors: Vec::new(),
        cost_usd: Some(0.0),
        observed_cost_usd: 0.0,
        unresolved_provider_spend: false,
        dry_run: true,
        first_chunk_error: None,
    }
}

pub(super) fn resolve_full_mode_model(runtime: &RoutedRuntime<'_>) -> Result<String> {
    if let Some(model) = runtime.resolve_model(AgentRole::FullModeMulti, 0, None) {
        crate::runtime::validate_model_spec(&model)
            .with_context(|| "full_mode_multi role resolved an invalid model")?;
        return Ok(model);
    }

    Err(anyhow::anyhow!(
        "no model configured for full_mode_multi role: \
         set models.toml [roles.full_mode_multi] or `setg MODEL_FULL_MODE_MULTI`"
    ))
}

pub(super) fn system_prompt_for_language(language: FullModeLanguage) -> String {
    match language {
        FullModeLanguage::C => SYSTEM_PROMPT_C,
        FullModeLanguage::Unknown => SYSTEM_PROMPT_UNKNOWN,
    }
    .to_string()
}
