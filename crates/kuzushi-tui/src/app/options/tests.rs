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
            default: None,
            choices: Vec::new(),
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
            json!("one,two")
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
    }

    #[test]
    fn coerce_raw_option_value_rejects_invalid_numbers_and_bools() {
        assert!(coerce_raw_option_value(&option_spec(OptionType::Bool), "maybe").is_err());
        assert!(coerce_raw_option_value(&option_spec(OptionType::Int), "many").is_err());
        assert!(coerce_raw_option_value(&option_spec(OptionType::Float), "NaN").is_err());
    }
}
