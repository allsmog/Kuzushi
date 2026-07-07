use super::*;

impl ShellApp {
    pub(crate) fn resolve_options_tool(&self, requested: Option<String>) -> Result<String> {
        match requested {
            Some(tool_name) => self.resolve_requested_options_tool(tool_name),
            None => self.default_options_tool(),
        }
    }

    /// The implicit options target when none is named: the open Options view,
    /// else the focused module's tool, else the SAST umbrella, else any tool.
    fn default_options_tool(&self) -> Result<String> {
        if matches!(self.shell_view, ShellView::Options) {
            let tool_name = &self.router.options().tool_name;
            if !tool_name.is_empty() {
                return Ok(tool_name.clone());
            }
        }
        self.default_tool_for_focused_module()
            .or_else(|| {
                self.registry()
                    .resolve_tool("sast:scan")
                    .map(|_| "sast:scan".to_string())
            })
            .or_else(|| self.registry().tools().next().map(|tool| tool.name.clone()))
            .context("no tools are loaded. Next: modules")
    }

    /// Resolve an explicitly-requested options target: `.` (focused module),
    /// a tool id (possibly module-prefixed), or a bare module id → its primary
    /// tool. Operators think in modules, so `options semgrep` must work.
    fn resolve_requested_options_tool(&self, tool_name: String) -> Result<String> {
        if tool_name == "." {
            return self
                .default_tool_for_focused_module()
                .context("`options .` requires a focused module. Next: use <module>");
        }
        self.lookup_options_tool(&tool_name).with_context(|| {
            format!("unknown tool {tool_name:?}. Next: `tools` to list, or `options {tool_name}:<verb>`")
        })
    }

    /// Map a requested name to a real tool id: module-prefixed form, exact tool
    /// id, or a bare module id resolved to its primary tool.
    fn lookup_options_tool(&self, tool_name: &str) -> Option<String> {
        let resolved = self.resolve_focused_tool_name(tool_name.to_string());
        if self.registry().resolve_tool(&resolved).is_some() {
            return Some(resolved);
        }
        if self.registry().resolve_tool(tool_name).is_some() {
            return Some(tool_name.to_string());
        }
        self.default_tool_for_module(tool_name)
    }

    pub(crate) fn current_options_filter(&self) -> OptionsFilter {
        if matches!(self.shell_view, ShellView::Options) {
            self.router.options().filter
        } else {
            OptionsFilter::Standard
        }
    }
}
