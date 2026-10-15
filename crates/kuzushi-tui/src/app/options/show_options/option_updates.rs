use super::*;

impl ShellApp {
    pub(crate) fn store_edited_tool_option(
        &mut self,
        tool: &str,
        spec: OptionSpec,
        value: serde_json::Value,
        global: bool,
    ) -> Vec<ShellEffect> {
        self.store_tool_option(
            global,
            ResolvedToolOption {
                tool_name: tool.into(),
                canonical_name: spec.name.clone(),
                spec,
            },
            value,
        )
    }
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
        let SetToolOptionWriteTarget {
            scope,
            target,
            prefix,
            is_role_model,
        } = set_tool_option_write_target(global, &option);
        self.option_store_mut().set_value(
            scope,
            target,
            option.canonical_name.clone(),
            value.clone(),
        );
        if !is_role_model {
            self.clear_legacy_global_tool_option(global, &option.canonical_name);
        }
        self.router.set_options(OptionsView {
            tool_name: option.tool_name.clone(),
            filter: self.current_options_filter(),
        });
        self.router.options_browser_mut().notice = None;
        self.set_shell_view(ShellView::Options);
        self.log(
            prefix,
            format!(
                "{}.{} = {}",
                option.tool_name,
                option.canonical_name,
                format_option_value(&value)
            ),
        );
        tool_option_effects(scope, &option.canonical_name)
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
        // Mirror the set path: `MODEL_<ROLE>` always writes to (Global, All), so
        // the unset must target (Global, All) too — otherwise a plain `unset
        // MODEL_<ROLE>` clears (Session, All), where nothing exists, and reports
        // "was not set" while the live router binding the operator just created
        // with plain `set` remains.
        let is_role_model = role_model_option(&option.canonical_name).is_some();
        let scope = if is_role_model {
            OptionScope::Global
        } else {
            scope
        };
        let target = role_model_write_target(target, is_role_model);
        let removed = self
            .option_store_mut()
            .unset_value(scope, &target, &option.canonical_name);
        let legacy_removed =
            !is_role_model && self.clear_legacy_global_tool_option(global, &option.canonical_name);
        self.router.set_options(OptionsView {
            tool_name: option.tool_name.clone(),
            filter: self.current_options_filter(),
        });
        self.router.options_browser_mut().notice = None;
        self.set_shell_view(ShellView::Options);
        self.log(
            prefix,
            removed_tool_option_message(&option, removed || legacy_removed),
        );
        tool_option_effects(scope, &option.canonical_name)
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
        if canonical_name == UI_AUTONOMY_OPTION {
            return Some(self.reduce_set_autonomy_option(global, value));
        }
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
        refresh_ui_prefs_from_store(self);
        self.log(
            if global { "setg" } else { "set" },
            format!("{canonical_name} = {value}"),
        );
        Some(persist_option_effects(scope))
    }

    fn reduce_set_autonomy_option(&mut self, global: bool, value: &str) -> Vec<ShellEffect> {
        if !global {
            self.log(
                "error",
                "ui.autonomy is global; use setg ui.autonomy <recon|scan|review|prove|fix>",
            );
            return Vec::new();
        }
        let Some(posture) = kuzushi_core::AutonomyPosture::parse(value) else {
            self.log(
                "error",
                "invalid ui.autonomy value; expected recon, scan, review, prove, or fix",
            );
            return Vec::new();
        };
        self.change_autonomy(posture);
        Vec::new()
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
        refresh_ui_prefs_from_store(self);
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

    pub(crate) fn persist_option_store(&mut self, scope: OptionScope) -> bool {
        if scope == OptionScope::Session {
            return true;
        }
        #[cfg(test)]
        if !self.option_persistence_enabled_for_test {
            return true;
        }
        let paths = match kuzushi_core::ConfigPaths::from_target(self.target()) {
            Ok(paths) => paths,
            Err(error) => {
                self.log(
                    "options",
                    format!("could not resolve option store path: {error}"),
                );
                return false;
            }
        };
        if let Err(error) = self.option_store_mut().save_persistent(
            &paths.global_options_path(),
            paths.project_options_path().as_deref(),
        ) {
            self.log("options", format!("could not persist options: {error}"));
            return false;
        }
        true
    }

    fn clear_legacy_global_tool_option(&mut self, global: bool, name: &str) -> bool {
        global
            && self
                .option_store_mut()
                .unset_value(OptionScope::Global, &OptionTarget::All, name)
    }
}

/// A `MODEL_<ROLE>` option maps to an agent-router role. These are cross-tool
/// policy, not per-tool knobs, so they bind at `OptionTarget::All`.
fn role_model_option(name: &str) -> Option<kuzushi_core::agent_router::AgentRole> {
    let key = name.strip_prefix("MODEL_")?;
    kuzushi_core::agent_router::AgentRole::from_key(&key.to_lowercase())
}

impl ShellApp {
    pub(crate) fn tool_option_has_global_scope(name: &str) -> bool {
        role_model_option(name).is_some()
    }
}

fn role_model_write_target(target: OptionTarget, is_role_model: bool) -> OptionTarget {
    if is_role_model {
        OptionTarget::All
    } else {
        target
    }
}

fn canonical_shell_option(name: &str) -> Option<&'static str> {
    match name.trim() {
        UI_AUTO_OPEN_ACTIVITY_OPTION | "auto_open_activity" => Some(UI_AUTO_OPEN_ACTIVITY_OPTION),
        UI_AUTO_OPEN_VIZ_OPTION | "auto_open_viz" => Some(UI_AUTO_OPEN_VIZ_OPTION),
        UI_AUTONOMY_OPTION | "autonomy" => Some(UI_AUTONOMY_OPTION),
        UI_RAIL_OPTION => Some(UI_RAIL_OPTION),
        UI_NOTIFY_OPTION => Some(UI_NOTIFY_OPTION),
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

struct SetToolOptionWriteTarget {
    scope: OptionScope,
    target: OptionTarget,
    prefix: &'static str,
    is_role_model: bool,
}

/// `MODEL_<ROLE>` is cross-tool router policy, so a plain `set` is promoted to
/// the durable `(Global, All)` binding the router actually reads. Ordinary
/// options retain the requested session/global tool scope.
fn set_tool_option_write_target(
    global: bool,
    option: &ResolvedToolOption,
) -> SetToolOptionWriteTarget {
    let write = tool_option_write_target(global, &option.tool_name, "set", "setg");
    let is_role_model = role_model_option(&option.canonical_name).is_some();
    if is_role_model {
        return SetToolOptionWriteTarget {
            scope: OptionScope::Global,
            target: OptionTarget::All,
            prefix: "setg",
            is_role_model,
        };
    }
    SetToolOptionWriteTarget {
        scope: write.scope,
        target: write.target,
        prefix: write.prefix,
        is_role_model,
    }
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

fn tool_option_effects(scope: OptionScope, option_name: &str) -> Vec<ShellEffect> {
    let mut effects = persist_option_effects(scope);
    if option_name == "identityFold" {
        effects.push(ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: None,
        }));
    }
    effects
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

#[cfg(test)]
mod identity_fold_effect_tests {
    use super::*;

    #[test]
    fn identity_fold_option_change_requests_a_filter_preserving_refresh() {
        let effects = tool_option_effects(OptionScope::Session, "identityFold");

        assert!(matches!(
            effects.as_slice(),
            [ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            })]
        ));
    }

    #[test]
    fn unrelated_session_option_does_not_reload_findings() {
        assert!(tool_option_effects(OptionScope::Session, "model").is_empty());
    }
}
