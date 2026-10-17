use super::*;
use crate::run_lifecycle::{RunItemStatus, RunProjection, SafeText};

mod load;
mod supplied_input;
pub use load::load_correlated_result_document;

const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_LINES: usize = 10_000;
const MAX_MESSAGES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResultDocument {
    pub status: RunItemStatus,
    pub summary: Vec<SafeText>,
    pub output: Vec<SafeText>,
    pub warnings: Vec<SafeText>,
    pub errors: Vec<SafeText>,
    /// Optional versioned supplied-input document. A read error does not hide the result.
    pub supplied_input: Option<std::result::Result<Vec<SafeText>, SafeText>>,
}

/// Select one exact result reference, never infer a filename for compound work.
pub fn single_result_artifact(
    projection: &RunProjection,
) -> Option<(RunItemId, RunItemStatus, &ArtifactReference)> {
    let tool_calls = projection
        .calls
        .values()
        .filter(|call| call.kind == crate::run_lifecycle::CallKind::Tool)
        .count();
    if tool_calls != 1 || projection.tasks.len() > 1 {
        return None;
    }
    let mut results = projection.calls.values().filter_map(|call| {
        call.result_artifact
            .as_ref()
            .map(|reference| (call.item_id, call.status, reference))
    });
    let result = results.next()?;
    results.next().is_none().then_some(result)
}

/// Authenticate cached bytes before exposing the saved output to a reader.
pub fn decode_correlated_result_document(
    producing_item_id: RunItemId,
    reference: &ArtifactReference,
    expected_status: RunItemStatus,
    body: &str,
) -> Result<RunResultDocument> {
    anyhow::ensure!(
        body.len() <= MAX_DOCUMENT_BYTES,
        "Saved result exceeds the 4 MiB reader limit"
    );
    super::validate_reference_identity(producing_item_id, reference)?;
    super::validate_reference_bytes(reference, body.as_bytes())?;
    super::validate_reference_lines(reference, body)?;
    let value: Value = serde_json::from_str(body).context("Saved result is malformed")?;
    anyhow::ensure!(
        value["status"].as_str() == Some(expected_status.label()),
        "Saved result status contradicts its call"
    );
    document_from_value(&value, expected_status)
}

fn document_from_value(value: &Value, expected_status: RunItemStatus) -> Result<RunResultDocument> {
    let mut document = RunResultDocument {
        status: expected_status,
        summary: display_text(value["summary"].as_str().unwrap_or(expected_status.label()))?,
        output: output_document(&value)?,
        warnings: document_messages(&value, "warnings")?,
        errors: document_messages(&value, "errors")?,
        supplied_input: None,
    };
    let bytes = [
        &document.summary,
        &document.output,
        &document.warnings,
        &document.errors,
    ]
    .into_iter()
    .flatten()
    .map(|line| line.as_str().len())
    .sum::<usize>();
    anyhow::ensure!(
        bytes <= MAX_DOCUMENT_BYTES,
        "Safe saved output exceeds the 4 MiB display limit"
    );
    document.supplied_input = supplied_input::decode(value, MAX_DOCUMENT_BYTES - bytes);
    Ok(document)
}

fn output_document(value: &Value) -> Result<Vec<SafeText>> {
    let Some(output) = value.get("output") else {
        return Ok(Vec::new());
    };
    let text = output.as_str().context("Saved output must be text")?;
    display_text(text)
}

fn display_text(text: &str) -> Result<Vec<SafeText>> {
    anyhow::ensure!(
        text.len() <= MAX_OUTPUT_BYTES,
        "Saved text exceeds the 512 KiB reader limit"
    );
    anyhow::ensure!(
        text.lines().count() <= MAX_OUTPUT_LINES,
        "Saved text exceeds the 10000-line reader limit"
    );
    let output = SafeText::document_lines(text);
    anyhow::ensure!(
        output.len() <= MAX_OUTPUT_LINES,
        "Saved text exceeds the 10000-row safe display limit"
    );
    Ok(output)
}

fn document_messages(value: &Value, field: &str) -> Result<Vec<SafeText>> {
    let Some(messages) = value.get(field) else {
        return Ok(Vec::new());
    };
    let messages = messages
        .as_array()
        .with_context(|| format!("Saved {field} must be a list"))?;
    anyhow::ensure!(
        messages.len() <= MAX_MESSAGES,
        "Saved {field} exceeds the 256-message reader limit"
    );
    let text = messages
        .iter()
        .map(|message| {
            message
                .as_str()
                .with_context(|| format!("Saved {field} contains a non-text message"))
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n");
    if text.is_empty() {
        return Ok(Vec::new());
    }
    display_text(&text)
}

#[cfg(test)]
mod tests;
