use anyhow::{Context, Result};
use kuzushi_core::modules::{OptionSpec, OptionType, ToolDescriptor};
use kuzushi_core::{OptionScope, OptionTarget};

use super::{OptionsFilter, OptionsView, ShellApp, ShellView};

impl ShellApp {
    pub(super) fn show_options(&mut self, tool: Option<String>, filter: OptionsFilter) {
        let tool_name = match self.resolve_options_tool(tool) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };

        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            "options",
            format!("showing {} for {tool_name}", options_filter_label(filter)),
        );
    }

    pub(super) fn set_option(&mut self, global: bool, name: &str, value: &str) {
        let tool_name = match self.resolve_options_tool(None) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let Some(tool) = self.registry.resolve_tool(&tool_name) else {
            self.log("error", format!("unknown tool {tool_name:?}. Next: tools"));
            return;
        };
        let Some(spec) = find_option_spec(tool, name) else {
            self.log("error", unknown_option_message(tool, name));
            return;
        };
        let canonical_name = spec.name.clone();
        let value = match coerce_raw_option_value(spec, value) {
            Ok(value) => value,
            Err(error) => {
                self.log(
                    "error",
                    format!(
                        "invalid value for {tool_name}.{canonical_name}: {error}. Next: show options {tool_name}"
                    ),
                );
                return;
            }
        };

        let (scope, target, prefix) = if global {
            (OptionScope::Global, OptionTarget::All, "setg")
        } else {
            (
                OptionScope::Session,
                OptionTarget::Tool(tool_name.clone()),
                "set",
            )
        };
        self.option_store
            .set_value(scope, target, canonical_name.clone(), value.clone());
        let filter = self.current_options_filter();
        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            prefix,
            format!(
                "{tool_name}.{canonical_name} = {}",
                format_option_value(&value)
            ),
        );
    }

    pub(super) fn unset_option(&mut self, global: bool, name: &str) {
        let tool_name = match self.resolve_options_tool(None) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let Some(tool) = self.registry.resolve_tool(&tool_name) else {
            self.log("error", format!("unknown tool {tool_name:?}. Next: tools"));
            return;
        };
        let Some(spec) = find_option_spec(tool, name) else {
            self.log("error", unknown_option_message(tool, name));
            return;
        };

        let (scope, target, prefix) = if global {
            (OptionScope::Global, OptionTarget::All, "unsetg")
        } else {
            (
                OptionScope::Session,
                OptionTarget::Tool(tool_name.clone()),
                "unset",
            )
        };
        let removed = self.option_store.unset_value(scope, &target, &spec.name);
        let filter = self.current_options_filter();
        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            prefix,
            if removed {
                format!("{tool_name}.{} cleared", spec.name)
            } else {
                format!(
                    "{tool_name}.{} was not set. Next: show options {tool_name}",
                    spec.name
                )
            },
        );
    }

    pub(crate) fn resolve_options_tool(&self, requested: Option<String>) -> Result<String> {
        if let Some(tool_name) = requested {
            // `options .` mirrors `run .` — operate on the focused module's
            // primary tool. The module-view footer hint advertises this
            // ("help options . · prompts · tune · back") so it must work.
            if tool_name == "." {
                if let Some(default) = self.default_tool_for_focused_module() {
                    return Ok(default);
                }
                anyhow::bail!("`options .` requires a focused module. Next: use <module>");
            }
            let resolved = self.resolve_focused_tool_name(tool_name.clone());
            if self.registry.resolve_tool(&resolved).is_some() {
                return Ok(resolved);
            }
            if self.registry.resolve_tool(&tool_name).is_some() {
                return Ok(tool_name);
            }
            anyhow::bail!("unknown tool {tool_name:?}. Next: tools");
        }

        if let ShellView::Options(view) = &self.shell_view {
            return Ok(view.tool_name.clone());
        }
        if let Some(tool_name) = self.default_tool_for_focused_module() {
            return Ok(tool_name);
        }
        if self.registry.resolve_tool("sast:scan").is_some() {
            return Ok("sast:scan".to_string());
        }
        self.registry
            .tools()
            .next()
            .map(|tool| tool.name.clone())
            .context("no tools are loaded. Next: modules")
    }

    pub(super) fn current_options_filter(&self) -> OptionsFilter {
        match &self.shell_view {
            ShellView::Options(view) => view.filter,
            _ => OptionsFilter::Standard,
        }
    }
}

fn options_filter_label(filter: OptionsFilter) -> &'static str {
    match filter {
        OptionsFilter::Standard => "options",
        OptionsFilter::Advanced => "advanced options",
        OptionsFilter::Missing => "missing options",
    }
}

fn find_option_spec<'a>(tool: &'a ToolDescriptor, name: &str) -> Option<&'a OptionSpec> {
    tool.options
        .iter()
        .find(|spec| spec.name.eq_ignore_ascii_case(name))
}

fn coerce_raw_option_value(spec: &OptionSpec, raw: &str) -> Result<serde_json::Value> {
    let raw = raw.trim();
    match spec.option_type {
        OptionType::String | OptionType::Path | OptionType::StringList => {
            Ok(raw_string_option_value(raw))
        }
        OptionType::Bool => Ok(serde_json::Value::Bool(parse_bool_option(raw)?)),
        OptionType::Int => coerce_raw_int_option(raw),
        OptionType::Float => coerce_raw_float_option(raw),
        OptionType::Enum => coerce_raw_enum_option(spec, raw),
    }
}

fn raw_string_option_value(raw: &str) -> serde_json::Value {
    serde_json::Value::String(raw.to_string())
}

fn coerce_raw_int_option(raw: &str) -> Result<serde_json::Value> {
    let parsed = raw
        .parse::<i64>()
        .with_context(|| format!("must be an integer, got {raw:?}"))?;
    Ok(serde_json::Value::Number(parsed.into()))
}

fn coerce_raw_float_option(raw: &str) -> Result<serde_json::Value> {
    let parsed = raw
        .parse::<f64>()
        .with_context(|| format!("must be a number, got {raw:?}"))?;
    let number = serde_json::Number::from_f64(parsed).context("must be a finite JSON number")?;
    Ok(serde_json::Value::Number(number))
}

fn coerce_raw_enum_option(spec: &OptionSpec, raw: &str) -> Result<serde_json::Value> {
    if !spec.choices.iter().any(|choice| choice == raw) {
        anyhow::bail!("must be one of {}, got {raw:?}", spec.choices.join("|"));
    }
    Ok(raw_string_option_value(raw))
}

fn parse_bool_option(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        _ => anyhow::bail!("must be true or false, got {value:?}"),
    }
}

fn format_option_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

fn unknown_option_message(tool: &ToolDescriptor, name: &str) -> String {
    let choices = tool
        .options
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<Vec<_>>();
    let closest = closest_option_names(name, &choices);
    let closest = if closest.is_empty() {
        "none".to_string()
    } else {
        closest.join(", ")
    };
    format!(
        "unknown option {name:?} for {}. Closest: {closest}. Next: show options {}",
        tool.name, tool.name
    )
}

pub(super) fn closest_option_names(name: &str, choices: &[&str]) -> Vec<String> {
    let normalized = name.to_ascii_lowercase();
    let mut scored = choices
        .iter()
        .map(|choice| {
            let choice_lower = choice.to_ascii_lowercase();
            let score =
                if choice_lower.starts_with(&normalized) || normalized.starts_with(&choice_lower) {
                    0
                } else {
                    edit_distance(&normalized, &choice_lower)
                };
            (score, (*choice).to_string())
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    scored
        .into_iter()
        .take(3)
        .filter(|(score, _)| *score <= normalized.len().max(3))
        .map(|(_, choice)| choice)
        .collect()
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left = left.chars().collect::<Vec<_>>();
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];

    for (i, left_ch) in left.iter().enumerate() {
        current[0] = i + 1;
        for (j, right_ch) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_ch != right_ch);
            let insertion = current[j] + 1;
            let deletion = previous[j + 1] + 1;
            current[j + 1] = substitution.min(insertion).min(deletion);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
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
