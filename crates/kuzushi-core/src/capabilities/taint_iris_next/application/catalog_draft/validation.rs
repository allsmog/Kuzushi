use super::*;

pub(super) fn validate(raw: &Value, sources: &[(String, String)]) -> Result<Vec<Value>> {
    let entries = raw
        .get("catalog")
        .and_then(Value::as_array)
        .context("Catalog response needs a catalog array")?;
    anyhow::ensure!(
        (1..=12).contains(&entries.len()),
        "Catalog must contain 1..=12 entries; no repair or extra model request is permitted"
    );
    for entry in entries {
        validate_entry(entry, sources)?;
    }
    let (normalized, error) = super::super::dynamic_catalog::parse_catalog_entries(Some(raw), &[]);
    anyhow::ensure!(
        error.is_none(),
        "Catalog shape is invalid: {}",
        error.unwrap_or_default()
    );
    normalized
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

fn validate_entry(entry: &Value, sources: &[(String, String)]) -> Result<()> {
    let object = entry
        .as_object()
        .context("Catalog entry must be an object")?;
    for key in object.keys() {
        anyhow::ensure!(
            [
                "cwe",
                "name",
                "taintClass",
                "languages",
                "sourceSignals",
                "sinkSignals",
                "sanitizerSignals",
                "structuralQueries",
                "regexMarkers",
                "score",
                "reasons"
            ]
            .contains(&key.as_str()),
            "Unknown catalog field {key}"
        );
    }
    validate_header(entry)?;
    validate_signals(entry, sources)?;
    validate_markers(entry, sources)
}

fn validate_header(entry: &Value) -> Result<()> {
    let cwe = required_text(entry, "cwe")?;
    let number = cwe
        .strip_prefix("CWE-")
        .context("Catalog CWE must use CWE-<number>")?;
    anyhow::ensure!(
        !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()),
        "Catalog CWE is invalid"
    );
    required_text(entry, "name")?;
    required_text(entry, "taintClass")?;
    let score = entry["score"]
        .as_i64()
        .context("Catalog score must be an explicit integer")?;
    anyhow::ensure!(
        (0..=100).contains(&score),
        "Catalog score must be 0..=100; it is not a verdict"
    );
    Ok(())
}

fn validate_signals(entry: &Value, sources: &[(String, String)]) -> Result<()> {
    let source = string_list(entry, "sourceSignals")?;
    let sink = string_list(entry, "sinkSignals")?;
    anyhow::ensure!(
        !source.is_empty() || !sink.is_empty(),
        "Catalog entry needs a grounded source or sink signal"
    );
    for signal in source
        .into_iter()
        .chain(sink)
        .chain(string_list(entry, "sanitizerSignals")?)
    {
        anyhow::ensure!(
            sources.iter().any(|(_, text)| text.contains(signal)),
            "Catalog signal {signal:?} does not occur in supplied source excerpts"
        );
    }
    anyhow::ensure!(
        !string_list(entry, "languages")?.is_empty(),
        "Catalog entry needs explicit languages or any"
    );
    string_list(entry, "structuralQueries")?;
    string_list(entry, "reasons")?;
    Ok(())
}

fn validate_markers(entry: &Value, sources: &[(String, String)]) -> Result<()> {
    let Some(markers) = entry.get("regexMarkers") else {
        return Ok(());
    };
    let markers = markers
        .as_array()
        .context("regexMarkers must be an array")?;
    anyhow::ensure!(markers.len() <= 4, "At most four regex markers per entry");
    for marker in markers {
        let pattern = required_text(marker, "pattern")?;
        let kind = required_text(marker, "kind")?;
        anyhow::ensure!(
            ["source", "sink", "entrypoint"].contains(&kind),
            "Invalid regex marker kind"
        );
        let regex = regex::Regex::new(pattern).context("Catalog regex marker is invalid")?;
        anyhow::ensure!(
            sources.iter().any(|(_, text)| regex.is_match(text)),
            "Catalog regex marker does not match supplied source excerpts"
        );
    }
    Ok(())
}

fn required_text<'a>(entry: &'a Value, name: &str) -> Result<&'a str> {
    let text = entry[name]
        .as_str()
        .context(format!("Catalog {name} must be text"))?;
    anyhow::ensure!(
        !text.trim().is_empty() && text.len() <= 512,
        "Catalog {name} must contain 1..=512 bytes"
    );
    Ok(text)
}

fn string_list<'a>(entry: &'a Value, name: &str) -> Result<Vec<&'a str>> {
    let Some(value) = entry.get(name) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .context(format!("Catalog {name} must be an array"))?;
    anyhow::ensure!(values.len() <= 12, "Catalog {name} exceeds twelve values");
    values
        .iter()
        .map(|value| {
            let text = value
                .as_str()
                .context(format!("Catalog {name} values must be text"))?;
            anyhow::ensure!(
                !text.trim().is_empty() && text.len() <= 512,
                "Catalog {name} values must contain 1..=512 bytes"
            );
            Ok(text)
        })
        .collect()
}
