use super::*;
use crate::runtime::AgentQueryResponse;

pub(super) fn validate(
    response: &AgentQueryResponse,
    maximum: usize,
) -> Result<Vec<DeepSemanticCweSelection>> {
    let value = raw_value(response)?;
    validate_classes(&value, maximum)
}

pub(crate) fn validate_classes(
    value: &Value,
    maximum: usize,
) -> Result<Vec<DeepSemanticCweSelection>> {
    require_fields(value, &["cwes"])?;
    let rows = value["cwes"]
        .as_array()
        .context("CWE response requires cwes[]")?;
    anyhow::ensure!(
        rows.len() <= maximum,
        "CWE response exceeds the approved class limit"
    );
    let classes = rows.iter().map(parse_row).collect::<Result<Vec<_>>>()?;
    let distinct = classes
        .iter()
        .map(|class| &class.id)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        distinct.len() == classes.len(),
        "CWE response contains duplicate ids"
    );
    Ok(classes)
}

pub(super) fn raw_value(response: &AgentQueryResponse) -> Result<Value> {
    anyhow::ensure!(
        response.text.len() <= 64 * 1024,
        "CWE response exceeds 64 KiB"
    );
    if let Some(value) = &response.structured {
        anyhow::ensure!(
            serde_json::to_vec(value)?.len() <= 64 * 1024,
            "Structured CWE response exceeds 64 KiB"
        );
        return Ok(value.clone());
    }
    serde_json::from_str(response.text.trim())
        .context("CWE response is malformed; no repair request was made")
}

fn parse_row(row: &Value) -> Result<DeepSemanticCweSelection> {
    require_fields(row, &["id", "name", "reason"])?;
    let id = text(row, "id", 32)?;
    let number = id
        .strip_prefix("CWE-")
        .and_then(|id| id.parse::<u32>().ok());
    anyhow::ensure!(
        number.is_some_and(|number| number > 0 && format!("CWE-{number}") == id),
        "CWE id must be CWE- followed by a positive integer"
    );
    Ok(DeepSemanticCweSelection {
        id,
        name: text(row, "name", 256)?,
        reason: text(row, "reason", 4096)?,
    })
}

fn require_fields(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .context("CWE contract requires a JSON object")?;
    anyhow::ensure!(
        object.len() == fields.len() && fields.iter().all(|name| object.contains_key(*name)),
        "CWE object must contain only {}",
        fields.join(", ")
    );
    Ok(())
}

fn text(row: &Value, field: &str, maximum: usize) -> Result<String> {
    let text = row[field]
        .as_str()
        .context(format!("CWE {field} must be text"))?
        .trim();
    anyhow::ensure!(
        !text.is_empty() && text.len() <= maximum,
        "CWE {field} must contain 1..={maximum} bytes"
    );
    Ok(text.into())
}
