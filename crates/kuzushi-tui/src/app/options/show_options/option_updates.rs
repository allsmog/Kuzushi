use super::*;

impl ShellApp {
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
        self.persist_option_store(scope);
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
        let canonical_name = spec.name.clone();

        let (scope, target, prefix) = if global {
            (OptionScope::Global, OptionTarget::All, "unsetg")
        } else {
            (
                OptionScope::Session,
                OptionTarget::Tool(tool_name.clone()),
                "unset",
            )
        };
        let removed = self
            .option_store
            .unset_value(scope, &target, &canonical_name);
        self.persist_option_store(scope);
        let filter = self.current_options_filter();
        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            prefix,
            if removed {
                format!("{tool_name}.{canonical_name} cleared")
            } else {
                format!("{tool_name}.{canonical_name} was not set. Next: show options {tool_name}")
            },
        );
    }

    fn persist_option_store(&mut self, scope: OptionScope) {
        if scope == OptionScope::Session {
            return;
        }
        let paths = match kuzushi_core::ConfigPaths::from_target(self.target.as_deref()) {
            Ok(paths) => paths,
            Err(error) => {
                self.log(
                    "options",
                    format!("could not resolve option store path: {error}"),
                );
                return;
            }
        };
        if let Err(error) = self.option_store.save_persistent(
            &paths.global_options_path(),
            paths.project_options_path().as_deref(),
        ) {
            self.log("options", format!("could not persist options: {error}"));
        }
    }
}
