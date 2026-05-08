use super::*;

impl ModuleRegistry {
    pub fn modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values().filter(|builtin| !builtin.is_hidden())
    }

    pub fn all_modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values()
    }

    pub fn tools(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.tools.values()
    }

    pub fn resolve_tool(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(name)
    }
}
