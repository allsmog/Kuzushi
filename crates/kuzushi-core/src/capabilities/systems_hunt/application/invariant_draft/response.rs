use super::*;

pub(super) fn validate(
    response: &AgentQueryResponse,
    prepared: &context::Prepared,
    maximum: usize,
) -> Result<Vec<SystemsInvariant>> {
    let value = raw_value(response)?;
    fields(&value, &["invariants"])?;
    let rows = value["invariants"]
        .as_array()
        .context("Invariant response requires invariants[]")?;
    anyhow::ensure!(
        rows.len() <= maximum,
        "Invariant response exceeds the approved draft limit"
    );
    let invariants = rows
        .iter()
        .map(|row| parse(row, prepared))
        .collect::<Result<Vec<_>>>()?;
    let ids = invariants
        .iter()
        .map(|row| &row.id)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        ids.len() == invariants.len(),
        "Invariant response contains duplicate ids"
    );
    Ok(invariants)
}

pub(super) fn raw_value(response: &AgentQueryResponse) -> Result<Value> {
    anyhow::ensure!(
        response.text.len() <= 64 * 1024,
        "Invariant response exceeds 64 KiB"
    );
    if let Some(value) = &response.structured {
        crate::checkpoint_limits::encode(value, 64 * 1024)
            .context("Structured invariant response exceeds 64 KiB")?;
        return Ok(value.clone());
    }
    serde_json::from_str(response.text.trim())
        .context("Invariant response is malformed; no repair request was made")
}

fn parse(row: &Value, prepared: &context::Prepared) -> Result<SystemsInvariant> {
    fields(
        row,
        &[
            "id",
            "surfaceId",
            "kind",
            "summary",
            "statement",
            "rationale",
            "evidence",
            "attackerControlledFields",
            "cheapVerifiable",
        ],
    )?;
    let surface_id = text(row, "surfaceId", 128)?;
    let source = prepared
        .surface_sources
        .get(&surface_id)
        .context("Invariant refers to a surface outside supplied prefixes")?;
    let evidence = strings(row, "evidence", 1, 8, 2048)?;
    anyhow::ensure!(
        evidence.iter().all(|quote| source.text.contains(quote)),
        "Invariant evidence is not a literal quote from its surface source prefix"
    );
    Ok(SystemsInvariant {
        id: text(row, "id", 128)?,
        surface_id,
        kind: text(row, "kind", 256)?,
        summary: text(row, "summary", 256)?,
        statement: text(row, "statement", 4096)?,
        rationale: text(row, "rationale", 4096)?,
        evidence,
        attacker_controlled_fields: strings(row, "attackerControlledFields", 0, 16, 256)?,
        cheap_verifiable: row["cheapVerifiable"]
            .as_bool()
            .context("cheapVerifiable must be a boolean unverified claim")?,
    })
}

fn fields(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .context("Invariant contract requires a JSON object")?;
    anyhow::ensure!(
        object.len() == expected.len() && expected.iter().all(|name| object.contains_key(*name)),
        "Invariant object must contain only {}",
        expected.join(", ")
    );
    Ok(())
}

fn text(row: &Value, field: &str, maximum: usize) -> Result<String> {
    bounded_text(&row[field], field, maximum)
}

fn bounded_text(value: &Value, field: &str, maximum: usize) -> Result<String> {
    let text = value
        .as_str()
        .context(format!("Invariant {field} must be text"))?;
    anyhow::ensure!(
        !text.trim().is_empty() && text.len() <= maximum,
        "Invariant {field} requires 1..={maximum} bytes of nonblank text"
    );
    Ok(text.into())
}

fn strings(
    row: &Value,
    field: &str,
    minimum: usize,
    maximum: usize,
    bytes: usize,
) -> Result<Vec<String>> {
    let values = row[field]
        .as_array()
        .context(format!("Invariant {field} must be an array"))?;
    anyhow::ensure!(
        (minimum..=maximum).contains(&values.len()),
        "Invariant {field} requires {minimum}..={maximum} entries"
    );
    values
        .iter()
        .map(|value| bounded_text(value, field, bytes))
        .collect()
}
