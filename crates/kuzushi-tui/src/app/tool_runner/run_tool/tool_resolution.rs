use super::*;

impl ShellApp {
    pub(crate) fn unknown_module_message(&self, module: &str) -> String {
        let module_ids = self
            .registry()
            .discoverable_modules()
            .map(|entry| entry.metadata().id.clone())
            .collect::<Vec<_>>();
        let module_refs = module_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let closest = closest_option_names(module, &module_refs);
        let closest = if closest.is_empty() {
            "none".to_string()
        } else {
            closest.join(", ")
        };
        format!("unknown module {module:?}. Closest: {closest}. Next: modules or use <module-id>")
    }

    pub(crate) fn default_tool_for_focused_module(&self) -> Option<String> {
        let module = self.focused_module()?;
        self.default_tool_for_module(module)
    }

    /// Preserve the registered primary action. An experimental primary requires
    /// an explicit tool choice instead of selecting a different kind of work.
    pub(crate) fn default_tool_for_module(&self, module: &str) -> Option<String> {
        if module == "verify" && self.registry().resolve_tool("verify:finding").is_some() {
            return Some("verify:finding".to_string());
        }
        if let Some(primary) = self
            .registry()
            .discoverable_modules()
            .find(|entry| entry.metadata().id == module)
            .and_then(|entry| entry.tools().iter().find(|tool| !tool.hidden))
        {
            return self
                .registry()
                .tool_is_discoverable(&primary.name)
                .then(|| primary.name.clone());
        }
        let prefix = format!("{module}:");
        self.registry()
            .discoverable_tools()
            .find(|tool| tool.name.starts_with(&prefix))
            .map(|tool| tool.name.clone())
    }

    pub(crate) fn default_tool_for_run_command(&self) -> Option<String> {
        if self.focused_module().is_some() {
            return self.default_tool_for_focused_module();
        }
        self.registry()
            .resolve_tool("sast:scan")
            .map(|_| "sast:scan".to_string())
    }

    pub(crate) fn resolve_focused_tool_name(&self, tool_name: String) -> String {
        if tool_name.contains(':') {
            return tool_name;
        }
        let Some(module) = self.focused_module() else {
            return tool_name;
        };
        let candidate = format!("{module}:{tool_name}");
        if self.registry().resolve_tool(&candidate).is_some() {
            candidate
        } else {
            tool_name
        }
    }
}
