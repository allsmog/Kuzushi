use super::*;

impl ModuleRegistry {
    pub fn modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values().filter(|builtin| !builtin.is_hidden())
    }

    pub fn all_modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values()
    }

    pub fn tools(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.tools.values().filter(|tool| self.is_tool_visible(tool))
    }

    pub fn resolve_tool(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(name)
    }

    fn is_tool_visible(&self, tool: &ToolDescriptor) -> bool {
        if tool.hidden {
            return false;
        }
        let Some((module_id, _)) = tool.name.split_once(':') else {
            return false;
        };
        self.modules
            .get(module_id)
            .is_some_and(|module| !module.is_hidden())
    }
}
