use super::prelude::*;
use super::*;

impl ShellApp {
    pub(crate) fn show_options(&mut self, tool: Option<String>, filter: OptionsFilter) {
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

    pub(crate) fn set_option(&mut self, global: bool, name: &str, value: &str) {
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

    pub(crate) fn unset_option(&mut self, global: bool, name: &str) {
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

    pub(crate) fn current_options_filter(&self) -> OptionsFilter {
        match &self.shell_view {
            ShellView::Options(view) => view.filter,
            _ => OptionsFilter::Standard,
        }
    }
}
