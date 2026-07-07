use super::*;

impl ModuleRegistry {
    pub fn modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values().filter(|builtin| !builtin.is_hidden())
    }

    pub fn all_modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values()
    }

    pub fn loaded_module_specifiers(&self) -> Vec<String> {
        self.all_modules()
            .map(|module| {
                self.dynamic_specifier_for_module(&module.metadata().id)
                    .unwrap_or_else(|| format!("builtin:{}", module.metadata().id))
            })
            .collect()
    }

    pub fn tools(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.tools
            .values()
            .filter(|tool| self.is_tool_visible(tool))
    }

    pub fn resolve_tool(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(name)
    }

    pub fn tool_needs_runtime(&self, name: &str, input: &Value) -> bool {
        let requirement = self
            .tools
            .get(name)
            .map(|tool| tool.runtime_requirement)
            .unwrap_or_else(|| {
                if self.is_registered_dag_node(name) && tool_uses_agent_runtime(name) {
                    RuntimeRequirement::Always
                } else {
                    RuntimeRequirement::Never
                }
            });
        match requirement {
            RuntimeRequirement::Never => false,
            RuntimeRequirement::Always => true,
            RuntimeRequirement::InputAware => tool_needs_runtime(name, input),
        }
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

    fn dynamic_specifier_for_module(&self, module_id: &str) -> Option<String> {
        self.dynamic_tools
            .values()
            .find(|binding| binding.module_id == module_id)
            .map(|binding| binding.specifier.clone())
    }
}
