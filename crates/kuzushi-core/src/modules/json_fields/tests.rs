#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn reads_aliases_and_trims_strings() {
        let object = json!({
            "file_path": " src/lib.rs ",
            "count": 7,
            "enabled": true,
            "nullable": null
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(
            read_object_string(&object, &["filePath", "file_path"]),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(read_object_u64(&object, &["count"]), Some(7));
        assert_eq!(read_object_bool(&object, &["enabled"]), Some(true));
        assert_eq!(read_object_nullable_string(&object, &["nullable"]), None);
    }

    #[test]
    fn normalizes_string_arrays_and_structured_citations() {
        let object = json!({
            "tags": [" one ", "", "two"],
            "codeCitations": [{
                "filePath": "src/lib.rs",
                "startLine": 3,
                "description": "source"
            }]
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(
            read_object_string_array(&object, &["tags"]),
            vec!["one", "two"]
        );
        assert_eq!(
            normalize_object_array(&object, &["tags"]),
            Some(json!(["one", "two"]))
        );
        assert_eq!(
            normalize_code_citations(&object).and_then(|value| value.as_array().map(Vec::len)),
            Some(1)
        );
    }

    #[test]
    fn parses_embedded_json_object_from_agent_text() {
        let parsed = parse_json_object_from_agent_text("analysis\n{\"ok\":true}\ntrailer").unwrap();
        assert_eq!(parsed["ok"], true);
    }
}
