use super::*;

pub(super) fn raw_value(response: &AgentQueryResponse) -> Result<Value> {
    anyhow::ensure!(
        response.text.len() <= 128 * 1024,
        "Discovery response exceeds 128 KiB"
    );
    if let Some(value) = &response.structured {
        anyhow::ensure!(
            serde_json::to_vec(value)?.len() <= 128 * 1024,
            "Structured discovery response exceeds 128 KiB"
        );
        return Ok(value.clone());
    }
    serde_json::from_str(response.text.trim())
        .context("Malformed discovery JSON; no repair request was made")
}

pub(super) fn validate(
    response: &AgentQueryResponse,
    prepared: &context::Prepared,
    maximum: usize,
) -> Result<Value> {
    let value = raw_value(response)?;
    let object = value
        .as_object()
        .context("Discovery response must be an object")?;
    anyhow::ensure!(
        object.len() == 1 && object.contains_key("findings"),
        "Discovery response requires only findings[]"
    );
    let items = value["findings"]
        .as_array()
        .context("Discovery findings must be an array")?;
    anyhow::ensure!(
        items.len() <= maximum,
        "Discovery response exceeds the approved finding limit"
    );
    for item in items {
        validate_item(item, prepared)?;
    }
    Ok(value)
}

fn validate_item(item: &Value, prepared: &context::Prepared) -> Result<()> {
    let object = item
        .as_object()
        .context("Discovery finding must be an object")?;
    let allowed = [
        "title",
        "filePath",
        "message",
        "startLine",
        "severity",
        "cwe",
        "evidence",
        "impact",
        "reasoningChain",
        "analysisPath",
    ];
    anyhow::ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "Discovery finding has unsupported fields"
    );
    text(item, "title", 256)?;
    text(item, "message", 8192)?;
    let path = text(item, "filePath", 4096)?;
    anyhow::ensure!(prepared.discovery.contains(path),"Finding path is not supplied discovery source; inherited context cannot become discovery work");
    validate_line(
        prepared,
        path,
        item["startLine"]
            .as_u64()
            .context("Finding startLine must be a positive integer")?,
    )?;
    anyhow::ensure!(
        ["critical", "high", "medium", "low", "info", "unknown"]
            .contains(&text(item, "severity", 32)?),
        "Invalid finding severity"
    );
    validate_classes(item, prepared)?;
    validate_evidence(item, prepared)?;
    validate_optional_text(item)
}

fn validate_classes(item: &Value, prepared: &context::Prepared) -> Result<()> {
    let values = string_values(&item["cwe"])?;
    anyhow::ensure!(
        !values.is_empty() && values.len() <= 32,
        "Finding requires bounded selected CWE ids"
    );
    let selected = prepared
        .classes
        .iter()
        .map(|class| class.id.as_str())
        .collect::<BTreeSet<_>>();
    let supplied = values.iter().copied().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        supplied.len() == values.len() && supplied.is_subset(&selected),
        "Finding CWE is duplicated or outside explicit selection"
    );
    Ok(())
}

fn string_values(value: &Value) -> Result<Vec<&str>> {
    if let Some(text) = value.as_str() {
        return Ok(vec![text]);
    }
    value
        .as_array()
        .context("Expected a text value or text array")?
        .iter()
        .map(|value| value.as_str().context("Array entry must be text"))
        .collect()
}

fn validate_evidence(item: &Value, prepared: &context::Prepared) -> Result<()> {
    let evidence = item["evidence"]
        .as_array()
        .context("Finding requires evidence[] anchors into supplied text")?;
    anyhow::ensure!(
        !evidence.is_empty() && evidence.len() <= 64,
        "Finding requires 1..64 evidence anchors"
    );
    for entry in evidence {
        let text = entry.as_str().context("Evidence must be text")?;
        anyhow::ensure!(text.len() <= 4096, "Evidence anchor exceeds 4096 bytes");
        let anchor = text.split(" - ").next().unwrap_or(text);
        let (path, line) = anchor
            .rsplit_once(':')
            .context("Evidence must name supplied file:line")?;
        validate_line(
            prepared,
            path,
            line.parse()
                .context("Evidence line must be a positive integer")?,
        )?;
    }
    Ok(())
}

fn validate_line(prepared: &context::Prepared, path: &str, line: u64) -> Result<()> {
    let source = prepared
        .sources
        .get(path)
        .context("Citation path is not in supplied source")?;
    anyhow::ensure!(
        line > 0 && line <= u32::MAX as u64 && line <= source.lines().count() as u64,
        "Citation line is outside supplied source text"
    );
    Ok(())
}

fn validate_optional_text(item: &Value) -> Result<()> {
    for key in ["impact", "reasoningChain"] {
        if item.get(key).is_some() {
            text(item, key, 16 * 1024)?;
        }
    }
    if let Some(value) = item.get("analysisPath") {
        let values = string_values(value)?;
        anyhow::ensure!(
            values.len() <= 64 && values.iter().all(|text| text.len() <= 4096),
            "Analysis path exceeds bounded text limits"
        );
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str, limit: usize) -> Result<&'a str> {
    let text = value[key]
        .as_str()
        .context(format!("Finding {key} must be text"))?;
    anyhow::ensure!(
        !text.trim().is_empty() && text.len() <= limit,
        "Finding {key} must contain 1..={limit} bytes"
    );
    Ok(text)
}
