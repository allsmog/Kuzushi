#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;

    fn option_spec(option_type: OptionType) -> OptionSpec {
        OptionSpec {
            name: "value".to_string(),
            option_type,
            description: String::new(),
            required: false,
            advanced: false,
            evasion: false,
            path_semantics: None,
            file_reference_semantics: None,
            default: None,
            minimum: None,
            maximum: None,
            choices: Vec::new(),
            aliases: Vec::new(),
            deprecated_aliases: Vec::new(),
        }
    }

    #[test]
    fn coerce_raw_option_value_covers_supported_shell_value_types() {
        assert_eq!(
            coerce_raw_option_value(&option_spec(OptionType::String), " text ").unwrap(),
            json!("text")
        );
        assert_eq!(
            coerce_raw_option_value(&option_spec(OptionType::Path), "./repo").unwrap(),
            json!("./repo")
        );
        assert_eq!(
            coerce_raw_option_value(&option_spec(OptionType::StringList), "one,two").unwrap(),
            json!(["one", "two"])
        );
        assert_eq!(
            coerce_raw_option_value(&option_spec(OptionType::Bool), "yes").unwrap(),
            json!(true)
        );
        assert_eq!(
            coerce_raw_option_value(&option_spec(OptionType::Int), "42").unwrap(),
            json!(42)
        );
        assert_eq!(
            coerce_raw_option_value(&option_spec(OptionType::Float), "1.25").unwrap(),
            json!(1.25)
        );

        let mut enum_spec = option_spec(OptionType::Enum);
        enum_spec.choices = vec!["auto".to_string(), "manual".to_string()];
        assert_eq!(
            coerce_raw_option_value(&enum_spec, "manual").unwrap(),
            json!("manual")
        );
        assert!(coerce_raw_option_value(&enum_spec, "other").is_err());
        let structured =
            coerce_raw_option_value(&option_spec(OptionType::Json), r#"{"enabled":true}"#)
                .unwrap_err();
        assert!(structured.to_string().contains("cannot be edited here"));
    }

    #[test]
    fn coerce_raw_option_value_rejects_invalid_numbers_and_bools() {
        assert!(coerce_raw_option_value(&option_spec(OptionType::Bool), "maybe").is_err());
        assert!(coerce_raw_option_value(&option_spec(OptionType::Int), "many").is_err());
        assert!(coerce_raw_option_value(&option_spec(OptionType::Float), "NaN").is_err());
    }

    #[test]
    fn option_values_render_without_serialized_json() {
        assert_eq!(format_option_value(&json!(true)), "yes");
        assert_eq!(format_option_value(&json!(["src", "tests"])), "src, tests");
        assert_eq!(format_option_value(&json!([1, 2])), "2 workflow values");
        assert_eq!(
            format_option_value(&json!({"token": "hidden"})),
            "1 workflow field"
        );
    }
}
