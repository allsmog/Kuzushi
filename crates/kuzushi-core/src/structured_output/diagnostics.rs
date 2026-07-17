use super::*;

pub(crate) const MAX_REPAIR_PROMPT_BYTES: usize = 32 * 1024;
pub(crate) const MAX_STRUCTURED_DIAGNOSTIC_BYTES: usize = 24 * 1024;
const MAX_SCHEMA_EXCERPT_BYTES: usize = 8 * 1024;
const MAX_ERROR_EXCERPT_BYTES: usize = 4 * 1024;
const MAX_RAW_RESPONSE_EXCERPT_BYTES: usize = 12 * 1024;
const MAX_FAILURE_RAW_EXCERPT_BYTES: usize = 6 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;

pub(super) fn build_repair_prompt(
    contract: &StructuredJsonContract,
    material: &ResponseMaterial,
    parse_error: &anyhow::Error,
) -> Result<String> {
    let tool = bounded_complete_text(&contract.tool_name, "tool name", MAX_IDENTIFIER_BYTES);
    let schema_name =
        bounded_complete_text(&contract.schema_name, "schema name", MAX_IDENTIFIER_BYTES);
    let failure = bounded_error(parse_error, MAX_ERROR_EXCERPT_BYTES)?;
    let schema = serialized_value_evidence(&contract.schema)?
        .render("required JSON schema", MAX_SCHEMA_EXCERPT_BYTES);
    let raw = material.render(MAX_RAW_RESPONSE_EXCERPT_BYTES);
    let prompt = format!(
        "The previous model response for `{tool}` did not satisfy `{schema_name}`.\n\n\
         Parse/validation failure (bounded evidence):\n{failure}\n\n\
         Required JSON schema (bounded evidence; the structured-output contract remains authoritative):\n{schema}\n\n\
         Invalid model response (bounded evidence, not the complete response unless no omission is marked):\n{raw}\n\n\
         Return only one valid JSON value matching `{schema_name}`. Do not include markdown fences or prose."
    );
    Ok(bounded_complete_text(
        &prompt,
        "repair prompt",
        MAX_REPAIR_PROMPT_BYTES,
    ))
}

pub(super) fn repair_failure_error(
    contract: &StructuredJsonContract,
    initial_error: &anyhow::Error,
    initial_material: &ResponseMaterial,
    repair_error: &anyhow::Error,
    repair_material: &ResponseMaterial,
) -> Result<anyhow::Error> {
    let tool = bounded_complete_text(&contract.tool_name, "tool name", MAX_IDENTIFIER_BYTES);
    let schema = bounded_complete_text(&contract.schema_name, "schema name", MAX_IDENTIFIER_BYTES);
    let initial_failure = bounded_error(initial_error, MAX_ERROR_EXCERPT_BYTES)?;
    let repair_failure = bounded_error(repair_error, MAX_ERROR_EXCERPT_BYTES)?;
    let initial_raw = initial_material.render(MAX_FAILURE_RAW_EXCERPT_BYTES);
    let repair_raw = repair_material.render(MAX_FAILURE_RAW_EXCERPT_BYTES);
    let message = format!(
        "{tool} could not satisfy structured JSON contract `{schema}` after one repair pass.\n\
         Initial parse/validation failure (bounded evidence):\n{initial_failure}\n\
         Repair parse/validation failure (bounded evidence):\n{repair_failure}\n\
         Initial model response (bounded evidence):\n{initial_raw}\n\
         Repair model response (bounded evidence):\n{repair_raw}"
    );
    Ok(anyhow::anyhow!(bounded_complete_text(
        &message,
        "structured-output failure diagnostic",
        MAX_STRUCTURED_DIAGNOSTIC_BYTES,
    )))
}

pub(super) fn truncation_error(
    contract: &StructuredJsonContract,
    response: &AgentQueryResponse,
    initial_error: &anyhow::Error,
    material: &ResponseMaterial,
) -> Result<anyhow::Error> {
    let tool = bounded_complete_text(&contract.tool_name, "tool name", MAX_IDENTIFIER_BYTES);
    let schema = bounded_complete_text(&contract.schema_name, "schema name", MAX_IDENTIFIER_BYTES);
    let stop_reason = bounded_complete_text(
        response.stop_reason.as_deref().unwrap_or("length"),
        "stop reason",
        MAX_IDENTIFIER_BYTES,
    );
    let failure = bounded_error(initial_error, MAX_ERROR_EXCERPT_BYTES)?;
    let raw = material.render(MAX_RAW_RESPONSE_EXCERPT_BYTES);
    let message = format!(
        "{tool} response was truncated by the per-call output-token cap \
         (stopReason: {stop_reason:?}); the partial JSON cannot satisfy \
         contract `{schema}`. Remediation: raise `AgentQueryRequest::max_output_tokens` \
         (or set `maxOutputTokens` in the tool input), reduce the requested output \
         size such as `maxFindings`, or shorten the prompt. \
         Initial parse/validation failure (bounded evidence):\n{failure}\n\
         Partial response (bounded evidence; source was truncated):\n{raw}"
    );
    Ok(anyhow::anyhow!(bounded_complete_text(
        &message,
        "structured-output truncation diagnostic",
        MAX_STRUCTURED_DIAGNOSTIC_BYTES,
    )))
}

fn bounded_error(error: &anyhow::Error, limit: usize) -> Result<String> {
    Ok(formatted_evidence(format_args!("{error:#}"))?.render("error", limit))
}

fn bounded_complete_text(value: &str, label: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_string();
    }
    ByteEvidence::from_bytes(value.as_bytes()).render(label, limit)
}
