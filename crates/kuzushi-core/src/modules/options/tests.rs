#[cfg(test)]
mod tests {
    use super::super::*;
    use super::super::{opt, tool_with_options};
    use serde_json::json;

    #[test]
    fn json_summary_formats_scalar_and_structured_values() {
        assert_eq!(json_summary(&json!("text")), "text");
        assert_eq!(json_summary(&json!(42)), "42");
        assert_eq!(json_summary(&json!(true)), "true");
        assert_eq!(json_summary(&Value::Null), "null");
        assert_eq!(json_summary(&json!({"a": 1})), r#"{"a":1}"#);
    }

    #[test]
    fn validates_and_coerces_declared_tool_options() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise option validation",
            vec![
                opt("enabled", OptionType::Bool, "boolean option").default(json!(false)),
                opt("limit", OptionType::Int, "integer option").default(json!(10)),
                opt("ratio", OptionType::Float, "floating-point option"),
                opt("target", OptionType::Path, "path option").required(),
                opt("label", OptionType::String, "string option"),
                opt("tags", OptionType::StringList, "string-list option"),
                opt("payload", OptionType::Json, "structured option"),
                opt("mode", OptionType::Enum, "enum option")
                    .choices(&["auto", "manual"])
                    .default(json!("auto")),
                opt("maxFindings", OptionType::Int, "aliased option").aliases(&["max_findings"]),
            ],
        );

        let validated = validate_tool_input_options(
            &descriptor,
            json!({
                "enabled": "yes",
                "limit": "42",
                "ratio": "0.75",
                "target": "./repo",
                "label": "baseline",
                "tags": ["one", "two"],
                "payload": {"nested": true},
                "mode": "manual",
                "max_findings": "7"
            }),
        )
        .unwrap();
        assert_eq!(validated["enabled"], json!(true));
        assert_eq!(validated["limit"], json!(42));
        assert_eq!(validated["ratio"], json!(0.75));
        assert_eq!(validated["target"], json!("./repo"));
        assert_eq!(validated["label"], json!("baseline"));
        assert_eq!(validated["tags"], json!(["one", "two"]));
        assert_eq!(validated["payload"], json!({"nested": true}));
        assert_eq!(validated["mode"], json!("manual"));
        assert_eq!(validated["maxFindings"], json!(7));
        assert_eq!(validated.get("max_findings"), None);

        let with_defaults = validate_tool_input_options(
            &descriptor,
            json!({
                "target": "./repo",
                "ratio": 1.25
            }),
        )
        .unwrap();
        assert_eq!(with_defaults["enabled"], json!(false));
        assert_eq!(with_defaults["limit"], json!(10));
        assert_eq!(with_defaults["mode"], json!("auto"));
    }

    #[test]
    fn rejects_unknown_options_with_declared_option_hint() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise strict option validation",
            vec![
                opt("target", OptionType::Path, "path option").required(),
                opt("maxFindings", OptionType::Int, "aliased option").aliases(&["max_findings"]),
            ],
        );

        let error = validate_tool_input_options(
            &descriptor,
            json!({
                "target": "./repo",
                "extra": true
            }),
        )
        .unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("unknown option \"extra\""), "{error}");
        assert!(error.contains("target"), "{error}");
        assert!(error.contains("maxFindings"), "{error}");
        assert!(error.contains("max_findings"), "{error}");
    }

    #[test]
    fn rejects_missing_required_and_invalid_option_values() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise option validation",
            vec![
                opt("enabled", OptionType::Bool, "boolean option"),
                opt("limit", OptionType::Int, "integer option"),
                opt("ratio", OptionType::Float, "floating-point option"),
                opt("target", OptionType::Path, "path option").required(),
                opt("mode", OptionType::Enum, "enum option").choices(&["auto", "manual"]),
            ],
        );

        for (input, expected) in [
            (json!({}), "requires option target"),
            (
                json!({"target": "./repo", "enabled": "maybe"}),
                "must be a boolean",
            ),
            (
                json!({"target": "./repo", "limit": "many"}),
                "must be an integer",
            ),
            (
                json!({"target": "./repo", "ratio": "wide"}),
                "must be a number",
            ),
            (
                json!({"target": "./repo", "mode": "toggle"}),
                "must be one of auto|manual",
            ),
            (json!({"target": "./repo", "extra": true}), "unknown option"),
        ] {
            let error = validate_tool_input_options(&descriptor, input).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(expected),
                "expected {error:?} to contain {expected:?}"
            );
        }
    }
}
