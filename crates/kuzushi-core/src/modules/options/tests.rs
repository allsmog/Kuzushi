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
                "tags": "one, two",
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
        assert!(!error.contains("Declare it in option metadata"), "{error}");
    }

    #[test]
    fn unknown_option_reports_close_match() {
        let descriptor = tool_with_options(
            "test:demo",
            "exercise strict option validation",
            vec![opt("maxFindings", OptionType::Int, "aliased option")],
        );

        let error = validate_tool_input_options(&descriptor, json!({"maxFinding": 7})).unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("Did you mean `maxFindings`?"), "{error}");
        assert!(error.contains("Next: use one of: maxFindings"), "{error}");
    }

    #[test]
    fn rejects_non_empty_input_when_no_options_are_declared() {
        let descriptor = tool_with_options("test:empty", "no input", vec![]);

        let empty = validate_tool_input_options(&descriptor, json!({})).unwrap();
        assert_eq!(empty, json!({}));

        let null = validate_tool_input_options(&descriptor, Value::Null).unwrap();
        assert_eq!(null, json!({}));

        let error = validate_tool_input_options(&descriptor, json!({ "extra": true }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown option \"extra\""), "{error}");
        assert!(error.contains("no options are declared"), "{error}");
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

    fn every_registered_descriptor() -> Vec<crate::modules::ToolDescriptor> {
        crate::modules::ModuleRegistry::with_v2_builtins()
            .all_modules()
            .flat_map(|module| module.tools().iter().cloned())
            .collect()
    }

    /// The registry-wide strictness contract: no tool, visible or hidden,
    /// accepts an undeclared input key. The unknown-key rejection fires
    /// before required-option checks, so this holds even for tools with
    /// required options.
    #[test]
    fn every_registered_tool_rejects_an_unknown_option_key() {
        for tool in every_registered_descriptor() {
            let error = validate_tool_input_options(
                &tool,
                json!({"kzq_definitely_unknown_option": true}),
            )
            .expect_err(&format!("{} accepted an unknown option key", tool.name));
            let error = format!("{error:#}");
            assert!(
                error.contains("unknown option"),
                "{}: expected an unknown-option rejection, got {error:?}",
                tool.name
            );
        }
    }

    /// Declared defaults must already be canonical for their option type:
    /// they are injected when the caller omits the option, so a mistyped
    /// default would hand every executor an invalid value.
    #[test]
    fn every_declared_default_is_canonical_for_its_option_type() {
        for tool in every_registered_descriptor() {
            for spec in &tool.options {
                let Some(default) = spec.default.clone() else {
                    continue;
                };
                let coerced = coerce_option_value(spec, default.clone()).unwrap_or_else(|error| {
                    panic!(
                        "{} option {} default {default:?} fails its own coercion: {error}",
                        tool.name, spec.name
                    )
                });
                assert_eq!(
                    coerced, default,
                    "{} option {} default is not canonical (coerces to {coerced:?})",
                    tool.name, spec.name
                );
            }
        }
    }

    /// Option resolution is first-match over case-insensitive names and
    /// aliases; a name claimed twice within one tool would resolve by
    /// declaration order, which is a silent precedence trap.
    #[test]
    fn option_names_and_aliases_are_unambiguous_within_each_tool() {
        for tool in every_registered_descriptor() {
            let mut seen = std::collections::BTreeMap::new();
            for spec in &tool.options {
                for key in std::iter::once(spec.name.as_str())
                    .chain(spec.aliases.iter().map(String::as_str))
                    .chain(spec.deprecated_aliases.iter().map(String::as_str))
                {
                    if let Some(owner) =
                        seen.insert(key.to_ascii_lowercase(), spec.name.clone())
                    {
                        assert_eq!(
                            owner, spec.name,
                            "{}: input key {key:?} is claimed by both {owner:?} and {:?}",
                            tool.name, spec.name
                        );
                    }
                }
            }
        }
    }

    /// A required option's default is unreachable (the required check fires
    /// first), so declaring both misdescribes the tool to operators.
    #[test]
    fn required_options_do_not_carry_unreachable_defaults() {
        for tool in every_registered_descriptor() {
            for spec in &tool.options {
                assert!(
                    !(spec.required && spec.default.is_some()),
                    "{} option {} is required but declares an unreachable default",
                    tool.name, spec.name
                );
            }
        }
    }

    /// Prepared tool input is persisted verbatim to `input.json`, and the
    /// unknown-key rejection means input can only carry DECLARED option
    /// names. Pinning that no descriptor declares a credential-shaped
    /// option keeps that artifact secret-free by construction; introducing
    /// one must be a conscious design decision with its own redaction.
    #[test]
    fn no_registered_option_name_or_alias_is_credential_shaped() {
        let secret_shaped = |name: &str| {
            let normalized = name
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase();
            // "token" alone would flag LLM token-count knobs like
            // maxTokensPerChunk; only auth-token shapes count.
            let credential_token = normalized.ends_with("token")
                || normalized.starts_with("token")
                || ["apitoken", "accesstoken", "refreshtoken", "authtoken"]
                    .iter()
                    .any(|needle| normalized.contains(needle));
            credential_token
                || [
                    "apikey",
                    "password",
                    "secret",
                    "credential",
                    "authorization",
                    "cookie",
                    "privatekey",
                ]
                .iter()
                .any(|needle| normalized.contains(needle))
        };
        for tool in every_registered_descriptor() {
            for option in &tool.options {
                let mut names = vec![option.name.clone()];
                names.extend(option.aliases.iter().cloned());
                names.extend(option.deprecated_aliases.iter().cloned());
                for name in names {
                    assert!(
                        !secret_shaped(&name),
                        "{} option {name:?} is credential-shaped; persisted \
                         input.json would carry the secret verbatim",
                        tool.name
                    );
                }
            }
        }
    }
}
