use super::*;

impl ShellApp {
    pub(crate) fn reduce_set_option(
        &mut self,
        global: bool,
        name: &str,
        value: &str,
    ) -> Vec<ShellEffect> {
        if let Some(effects) = self.reduce_set_shell_option(global, name, value) {
            return effects;
        }
        let Some(option) = self.resolve_tool_option(name) else {
            return Vec::new();
        };
        let Some(value) = self.coerce_tool_option_value(&option, value) else {
            return Vec::new();
        };
        self.store_tool_option(global, option, value)
    }

    fn store_tool_option(
        &mut self,
        global: bool,
        option: ResolvedToolOption,
        value: serde_json::Value,
    ) -> Vec<ShellEffect> {
        let ToolOptionWriteTarget {
            scope,
            target,
            prefix,
        } = tool_option_write_target(global, &option.tool_name, "set", "setg");
        self.option_store_mut().set_value(
            scope,
            target,
            option.canonical_name.clone(),
            value.clone(),
        );
        self.clear_legacy_global_tool_option(global, &option.canonical_name);
        self.router.set_options(OptionsView {
            tool_name: option.tool_name.clone(),
            filter: self.current_options_filter(),
        });
        self.shell_view = ShellView::Options;
        self.log(
            prefix,
            format!(
                "{}.{} = {}",
                option.tool_name,
                option.canonical_name,
                format_option_value(&value)
            ),
        );
        persist_option_effects(scope)
    }

    pub(crate) fn reduce_unset_option(&mut self, global: bool, name: &str) -> Vec<ShellEffect> {
        if let Some(effects) = self.reduce_unset_shell_option(global, name) {
            return effects;
        }
        let Some(option) = self.resolve_tool_option(name) else {
            return Vec::new();
        };
        self.remove_tool_option(global, option)
    }

    fn remove_tool_option(&mut self, global: bool, option: ResolvedToolOption) -> Vec<ShellEffect> {
        let ToolOptionWriteTarget {
            scope,
            target,
            prefix,
        } = tool_option_write_target(global, &option.tool_name, "unset", "unsetg");
        let removed = self
            .option_store_mut()
            .unset_value(scope, &target, &option.canonical_name);
        let legacy_removed = self.clear_legacy_global_tool_option(global, &option.canonical_name);
        self.router.set_options(OptionsView {
            tool_name: option.tool_name.clone(),
            filter: self.current_options_filter(),
        });
        self.shell_view = ShellView::Options;
        self.log(
            prefix,
            removed_tool_option_message(&option, removed || legacy_removed),
        );
        persist_option_effects(scope)
    }

    fn resolve_tool_option(&mut self, name: &str) -> Option<ResolvedToolOption> {
        let tool_name = match self.resolve_options_tool(None) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return None;
            }
        };
        let Some(tool) = self.registry().resolve_tool(&tool_name) else {
            self.log("error", format!("unknown tool {tool_name:?}. Next: tools"));
            return None;
        };
        let Some(spec) = find_option_spec(tool, name) else {
            self.log("error", unknown_option_message(tool, name));
            return None;
        };
        Some(ResolvedToolOption {
            tool_name,
            canonical_name: spec.name.clone(),
            spec: spec.clone(),
        })
    }

    fn coerce_tool_option_value(
        &mut self,
        option: &ResolvedToolOption,
        value: &str,
    ) -> Option<serde_json::Value> {
        coerce_raw_option_value(&option.spec, value)
            .map_err(|error| {
                self.log(
                    "error",
                    invalid_tool_option_message(option, error.to_string()),
                );
            })
            .ok()
    }

    fn reduce_set_shell_option(
        &mut self,
        global: bool,
        name: &str,
        value: &str,
    ) -> Option<Vec<ShellEffect>> {
        let Some(canonical_name) = canonical_shell_option(name) else {
            return None;
        };
        let Some(value) = parse_bool_pref(value) else {
            self.log(
                "error",
                format!(
                    "invalid value for {canonical_name}: expected true/false, on/off, yes/no, or 1/0"
                ),
            );
            return Some(Vec::new());
        };
        let scope = if global {
            OptionScope::Global
        } else {
            OptionScope::Session
        };
        self.option_store_mut().set_value(
            scope,
            OptionTarget::All,
            canonical_name,
            serde_json::Value::Bool(value),
        );
        refresh_auto_open_prefs_from_store(self);
        self.log(
            if global { "setg" } else { "set" },
            format!("{canonical_name} = {value}"),
        );
        Some(persist_option_effects(scope))
    }

    fn reduce_unset_shell_option(&mut self, global: bool, name: &str) -> Option<Vec<ShellEffect>> {
        let Some(canonical_name) = canonical_shell_option(name) else {
            return None;
        };
        let scope = if global {
            OptionScope::Global
        } else {
            OptionScope::Session
        };
        let removed =
            self.option_store_mut()
                .unset_value(scope, &OptionTarget::All, canonical_name);
        refresh_auto_open_prefs_from_store(self);
        self.log(
            if global { "unsetg" } else { "unset" },
            if removed {
                format!("{canonical_name} cleared")
            } else {
                format!("{canonical_name} was not set")
            },
        );
        Some(persist_option_effects(scope))
    }

    pub(crate) fn persist_option_store(&mut self, scope: OptionScope) {
        if scope == OptionScope::Session {
            return;
        }
        #[cfg(test)]
        if !self.option_persistence_enabled_for_test {
            return;
        }
        let paths = match kuzushi_core::ConfigPaths::from_target(self.target()) {
            Ok(paths) => paths,
            Err(error) => {
                self.log(
                    "options",
                    format!("could not resolve option store path: {error}"),
                );
                return;
            }
        };
        if let Err(error) = self.option_store_mut().save_persistent(
            &paths.global_options_path(),
            paths.project_options_path().as_deref(),
        ) {
            self.log("options", format!("could not persist options: {error}"));
        }
    }

    fn clear_legacy_global_tool_option(&mut self, global: bool, name: &str) -> bool {
        global
            && self
                .option_store_mut()
                .unset_value(OptionScope::Global, &OptionTarget::All, name)
    }
}

fn canonical_shell_option(name: &str) -> Option<&'static str> {
    match name.trim() {
        UI_AUTO_OPEN_ACTIVITY_OPTION | "auto_open_activity" => Some(UI_AUTO_OPEN_ACTIVITY_OPTION),
        UI_AUTO_OPEN_VIZ_OPTION | "auto_open_viz" => Some(UI_AUTO_OPEN_VIZ_OPTION),
        UI_WORKBENCH_DEPTH_STACK_OPTION | "workbench_depth_stack" => {
            Some(UI_WORKBENCH_DEPTH_STACK_OPTION)
        }
        _ => None,
    }
}

struct ResolvedToolOption {
    tool_name: String,
    canonical_name: String,
    spec: OptionSpec,
}

struct ToolOptionWriteTarget {
    scope: OptionScope,
    target: OptionTarget,
    prefix: &'static str,
}

fn tool_option_write_target(
    global: bool,
    tool_name: &str,
    session_prefix: &'static str,
    global_prefix: &'static str,
) -> ToolOptionWriteTarget {
    if global {
        return ToolOptionWriteTarget {
            scope: OptionScope::Global,
            target: OptionTarget::Tool(tool_name.to_string()),
            prefix: global_prefix,
        };
    }
    ToolOptionWriteTarget {
        scope: OptionScope::Session,
        target: OptionTarget::Tool(tool_name.to_string()),
        prefix: session_prefix,
    }
}

fn persist_option_effects(scope: OptionScope) -> Vec<ShellEffect> {
    if scope == OptionScope::Session {
        Vec::new()
    } else {
        vec![ShellEffect::PersistOptions(scope)]
    }
}

fn invalid_tool_option_message(option: &ResolvedToolOption, error: String) -> String {
    format!(
        "invalid value for {}.{}: {error}. Next: show options {}",
        option.tool_name, option.canonical_name, option.tool_name
    )
}

fn removed_tool_option_message(option: &ResolvedToolOption, removed: bool) -> String {
    if removed {
        return format!("{}.{} cleared", option.tool_name, option.canonical_name);
    }
    format!(
        "{}.{} was not set. Next: show options {}",
        option.tool_name, option.canonical_name, option.tool_name
    )
}
