use super::*;

/// Decode operator text before canonical typed validation. JSON inputs retain
/// their existing byte-preserving string contract through coerce_option_value.
pub fn coerce_option_text(spec: &OptionSpec, raw: &str) -> Result<Value> {
    let value = operator_text_value(spec, raw)?;
    coerce_option_value(spec, value)
}

fn operator_text_value(spec: &OptionSpec, raw: &str) -> Result<Value> {
    let text = raw.trim();
    if spec.option_type == OptionType::Json && spec.editable_json {
        return serde_json::from_str(text).context("setting requires a complete JSON value");
    }
    if spec.option_type == OptionType::StringList {
        return operator_string_list_value(text);
    }
    if matches!(spec.option_type, OptionType::String | OptionType::Path) && text.starts_with('"') {
        let decoded = serde_json::from_str::<String>(text)
            .context("quoted text must be a complete JSON string")?;
        return Ok(Value::String(decoded));
    }
    Ok(Value::String(text.to_string()))
}

fn operator_string_list_value(text: &str) -> Result<Value> {
    if text.starts_with('[') {
        let entries = serde_json::from_str::<Vec<String>>(text)
            .context("list must be a complete JSON array of strings, or comma-separated text")?;
        return Ok(serde_json::json!(entries));
    }
    if text.starts_with('"') {
        let entry = serde_json::from_str::<String>(text)
            .context("quoted list entry must be a complete JSON string")?;
        return Ok(serde_json::json!([entry]));
    }
    Ok(Value::String(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editable_json_requires_complete_text_and_preserves_typed_values() {
        let spec = opt("pairs", OptionType::Json, "operator JSON").editable_json();
        for value in [
            serde_json::json!([{"alloc":"owned", "free":"release"}]),
            serde_json::json!("[1]"),
            serde_json::json!(true),
            serde_json::json!(null),
        ] {
            assert_eq!(
                coerce_option_text(&spec, &value.to_string()).unwrap(),
                value
            );
            assert_eq!(coerce_option_value(&spec, value.clone()).unwrap(), value);
        }
        for invalid in ["[{ unfinished", "unquoted text", "[1] trailing"] {
            assert!(coerce_option_text(&spec, invalid).is_err());
        }
    }

    #[test]
    fn quoted_operator_paths_preserve_spaces_and_escape_sequences() {
        let path = opt("binary", OptionType::Path, "executable");
        assert_eq!(
            coerce_option_text(&path, r#""/owned scanner ""#).unwrap(),
            Value::String("/owned scanner ".into())
        );
        assert_eq!(
            coerce_option_text(&path, r#""/owned/quote\"name""#).unwrap(),
            Value::String("/owned/quote\"name".into())
        );
        assert_eq!(
            coerce_option_text(&path, "  /owned/scanner  ").unwrap(),
            Value::String("/owned/scanner".into())
        );
    }

    #[test]
    fn malformed_quotes_fail_without_reinterpreting_typed_json_strings() {
        let spec = opt("label", OptionType::String, "text");
        assert!(coerce_option_text(&spec, "\"unfinished").is_err());
        assert_eq!(
            coerce_option_value(&spec, Value::String("\"literal\"".into())).unwrap(),
            Value::String("\"literal\"".into())
        );
    }

    #[test]
    fn operator_lists_preserve_array_members_and_quoted_single_entries() {
        let spec = opt("rules", OptionType::StringList, "rule files");
        assert_eq!(
            coerce_option_text(&spec, r#"["/owned/rule,one.yaml","/owned/rule two.yaml"]"#)
                .unwrap(),
            serde_json::json!(["/owned/rule,one.yaml", "/owned/rule two.yaml"])
        );
        assert_eq!(
            coerce_option_text(&spec, r#""/owned/rule,one.yaml""#).unwrap(),
            serde_json::json!(["/owned/rule,one.yaml"])
        );
        assert_eq!(
            coerce_option_text(&spec, "one,two").unwrap(),
            serde_json::json!(["one", "two"])
        );
        for invalid in ["[\"unfinished", "[\"rule\",1]", "\"unfinished"] {
            assert!(coerce_option_text(&spec, invalid).is_err());
        }
    }
}
