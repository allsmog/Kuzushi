use super::*;

pub(crate) const LEAF: &str = "rejected-context-output.txt";

pub(crate) fn validate_requested_mode(input: &Value) -> Result<()> {
    let selected = input
        .get("saveRejectedOutput")
        .or_else(|| input.get("save_rejected_output"));
    if selected != Some(&Value::Bool(true)) {
        return Ok(());
    }
    anyhow::ensure!(
        input["pipeline"].as_str().unwrap_or("single") == "single"
            && input["mode"].as_str().unwrap_or("build") == "build",
        "saveRejectedOutput currently supports single synthesis in build mode only"
    );
    Ok(())
}

pub(crate) fn validate(input: &BuildInput, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    if !input.save_rejected_output {
        return Ok(());
    }
    let (target, _) = ctx
        .run_artifact_location()
        .context("saveRejectedOutput requires a durable run")?;
    anyhow::ensure!(
        std::fs::canonicalize(target)? == std::fs::canonicalize(input.workspace_root())?,
        "rejected output must remain in its owning run workspace"
    );
    Ok(())
}

pub(crate) fn retain(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
    error: anyhow::Error,
) -> anyhow::Error {
    if !input.save_rejected_output {
        return error;
    }
    let Some(body) = crate::structured_output::rejected_output_diagnostic(&error) else {
        return error;
    };
    match persist(ctx, &body) {
        Ok(_) => error.context(format!("Rejected context output saved as {LEAF}; inspect locally. No context accepted.")),
        Err(_) => error.context("Rejected context output could not be saved; inspect the failed run. No context accepted."),
    }
}

fn persist(
    ctx: &ToolExecutionContext<'_>,
    body: &str,
) -> Result<crate::run_artifacts::RunArtifact> {
    let (target, run_id) = ctx
        .run_artifact_location()
        .context("rejected output requires a durable run")?;
    crate::run_artifacts::write_run_artifact_text(
        target,
        &run_id,
        LEAF,
        "Rejected context output: unaccepted, may contain source text",
        "text",
        body,
    )
}

pub(crate) fn retain_unrepaired_response(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
    response: &crate::runtime::AgentQueryResponse,
    error: anyhow::Error,
) -> anyhow::Error {
    if !input.save_rejected_output {
        return error;
    }
    let body = match bounded_response_diagnostic(response) {
        Ok(body) => body,
        Err(_) => {
            return error
                .context("Rejected response exceeds the diagnostic limit; no context accepted")
        }
    };
    match persist(ctx, &body) {
        Ok(_) => error.context(format!(
            "Rejected context output saved as {LEAF}; no model repair request was made"
        )),
        Err(_) => error.context("Rejected context output could not be saved; no context accepted"),
    }
}

fn bounded_response_diagnostic(response: &crate::runtime::AgentQueryResponse) -> Result<String> {
    crate::structured_output::ensure_response_material_budget(response)?;
    let text = match &response.structured {
        Some(value) => serde_json::to_string(value)?,
        None => response.text.clone(),
    };
    let end = text
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= 16 * 1024)
        .last()
        .unwrap_or(0);
    let end = if text.len() <= 16 * 1024 {
        text.len()
    } else {
        end
    };
    Ok(format!("Unaccepted file-group context. No model repair request. Diagnostic excerpt: {} of {} bytes.\n{}",end,text.len(),&text[..end]))
}

#[cfg(test)]
mod tests;
