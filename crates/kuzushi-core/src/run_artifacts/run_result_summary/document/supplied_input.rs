use super::*;

pub(super) fn decode(
    value: &Value,
    remaining: usize,
) -> Option<std::result::Result<Vec<SafeText>, SafeText>> {
    let document = value.get("data")?.get("inputDocument")?;
    Some(
        parse(document, remaining)
            .map_err(|error| SafeText::operator_visible(format!("{error:#}"))),
    )
}

fn parse(value: &Value, remaining: usize) -> Result<Vec<SafeText>> {
    anyhow::ensure!(
        value["schemaVersion"].as_u64() == Some(1),
        "Supplied input uses an unsupported document version"
    );
    if let Some(error) = value["error"].as_str() {
        anyhow::bail!("{error}");
    }
    let text = value["text"]
        .as_str()
        .context("Supplied input document must contain text")?;
    anyhow::ensure!(!text.is_empty(), "Supplied input document is empty");
    let rows = display_text(text)?;
    anyhow::ensure!(
        rows.iter().map(|row| row.as_str().len()).sum::<usize>() <= remaining,
        "Supplied input exceeds the remaining safe display allowance"
    );
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn optional_inputs_preserve_blank_source_lines_and_safely_display_controls() {
        assert_eq!(decode(&json!({"data":{}}), MAX_DOCUMENT_BYTES), None);
        let rows = decode(
            &json!({"data":{"inputDocument":{"schemaVersion":1,
            "text":"Owned source\n\n  café\u{1b}[31m"}}}),
            MAX_DOCUMENT_BYTES,
        )
        .unwrap()
        .unwrap();
        let text = rows
            .iter()
            .map(|row| row.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Owned source\n\n  café"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn malformed_unknown_or_excessive_inputs_are_explicit_reader_errors() {
        for input in [
            json!(null),
            json!({"schemaVersion":2,"text":"owned"}),
            json!({"schemaVersion":1,"text":42}),
            json!({"schemaVersion":1,"text":""}),
            json!({"schemaVersion":1,"text":"x".repeat(MAX_OUTPUT_BYTES+1)}),
        ] {
            assert!(
                decode(&json!({"data":{"inputDocument":input}}), MAX_DOCUMENT_BYTES)
                    .unwrap()
                    .is_err()
            );
        }
        assert!(decode(
            &json!({"data":{"inputDocument":{"schemaVersion":1,"text":"owned"}}}),
            1
        )
        .unwrap()
        .is_err());
    }

    #[test]
    fn retained_input_failure_is_readable_without_hiding_the_result() {
        let value = json!({"data":{"inputDocument":{"schemaVersion":1,
            "error":"Prepared input changed since retention"}}});
        let error = decode(&value, MAX_DOCUMENT_BYTES).unwrap().unwrap_err();
        assert!(error.as_str().contains("changed since retention"));
    }
}
