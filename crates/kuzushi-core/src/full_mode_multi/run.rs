use super::prelude::*;
use super::*;

pub fn run(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
) -> Result<FullModeReport> {
    let plan = plan(cfg).context("full_mode_multi: planning failed")?;

    if cfg.dry_run {
        return Ok(FullModeReport {
            findings: Vec::new(),
            plan,
            chunks_dispatched: 0,
            chunks_failed: 0,
            cost_usd: 0.0,
            dry_run: true,
        });
    }

    let model = runtime
        .resolve_model(AgentRole::FullModeMulti, 0, None)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no model configured for full_mode_multi role: \
                 set models.toml [roles.full_mode_multi] or `setg MODEL_FULL_MODE_MULTI`"
            )
        })?;
    let system_prompt = match cfg.language {
        FullModeLanguage::C => SYSTEM_PROMPT_C,
        FullModeLanguage::Unknown => SYSTEM_PROMPT_UNKNOWN,
    }
    .to_string();

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut dispatched = 0u32;
    let mut failed = 0u32;
    let mut cost = 0.0f64;

    for chunk in &plan.chunks {
        let ticket = match spend {
            Some(limiter) => Some(
                limiter
                    .deposit(Operation::FullModeMulti, cfg.deposit_usd_per_chunk)
                    .context("full_mode_multi: deposit failed")?,
            ),
            None => None,
        };

        let prompt = render_chunk_prompt(&cfg.workspace_root, chunk)?;
        let request = AgentQueryRequest::new(
            model.clone(),
            cfg.workspace_root.clone(),
            system_prompt.clone(),
            prompt,
        );

        let result = query_required_structured_json(
            runtime,
            request,
            StructuredJsonContract::new(
                "full-mode-multi:chunk",
                "FullModeFindingArray",
                full_mode_findings_schema(),
            ),
            parse_chunk_value,
        );

        let actual_cost = match &result {
            Ok(_) => cfg.deposit_usd_per_chunk, // bridge cost surfaces in Phase 5c+
            Err(_) => 0.0,
        };
        if let (Some(limiter), Some(t)) = (spend, ticket) {
            // Refund must succeed even on chunk failure — we can't strand
            // the budget.
            limiter.refund(t, actual_cost)?;
        }

        match result {
            Ok(chunk_findings) => {
                cost += actual_cost;
                dispatched += 1;
                all_findings.extend(chunk_findings);
            }
            Err(_error) => {
                failed += 1;
                // Continue — one bad chunk shouldn't kill the whole pass.
            }
        }
    }

    Ok(FullModeReport {
        findings: all_findings,
        plan,
        chunks_dispatched: dispatched,
        chunks_failed: failed,
        cost_usd: cost,
        dry_run: false,
    })
}
