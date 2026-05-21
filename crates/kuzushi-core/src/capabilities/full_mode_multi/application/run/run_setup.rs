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
        cost_usd: 0.0,
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

    if let Ok(model) = std::env::var(AgentRole::FullModeMulti.option_store_key()) {
        let trimmed = model.trim();
        if !trimmed.is_empty() {
            crate::runtime::validate_model_spec(trimmed)
                .with_context(|| "MODEL_FULL_MODE_MULTI contains an invalid model")?;
            return Ok(trimmed.to_string());
        }
    }

    Err(anyhow::anyhow!(
        "no model configured for full_mode_multi role: \
         set models.toml [roles.full_mode_multi], `setg MODEL_FULL_MODE_MULTI`, \
         or export MODEL_FULL_MODE_MULTI=<model>"
    ))
}

pub(super) fn system_prompt_for_language(language: FullModeLanguage) -> String {
    match language {
        FullModeLanguage::C => SYSTEM_PROMPT_C,
        FullModeLanguage::Unknown => SYSTEM_PROMPT_UNKNOWN,
    }
    .to_string()
}
