use super::*;

impl ShellApp {
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
