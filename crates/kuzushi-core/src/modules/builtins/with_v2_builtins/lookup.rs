use super::*;
use crate::modules::runtime_requirements::input_aware_tool_needs_runtime;
use crate::modules::runtime_requirements::tool_optionally_wants_runtime;
use crate::V2Config;

impl ModuleRegistry {
    pub fn tool_requires_finding_store(&self, name: &str) -> bool {
        self.resolve_tool(name)
            .is_some_and(|tool| tool.finding_store_requirement == FindingStoreRequirement::Required)
    }

    pub fn tool_requires_workspace(&self, name: &str) -> bool {
        self.resolve_tool(name)
            .is_some_and(|tool| tool.workspace_requirement == WorkspaceRequirement::Required)
    }

    /// Every operator-visible module, preserving the original registry API.
    pub fn modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules.values().filter(|builtin| !builtin.is_hidden())
    }

    /// Default discovery surface: visible Core modules only.
    pub fn discoverable_modules(&self) -> impl Iterator<Item = &BuiltinModule> {
        self.modules()
            .filter(|builtin| builtin.maturity().is_core())
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

    /// Every operator-visible tool, preserving the original registry API.
    pub fn tools(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.tools
            .values()
            .filter(|tool| self.is_tool_visible(tool))
    }

    /// Default discovery surface: visible tools owned by Core modules only.
    pub fn discoverable_tools(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.tools().filter(|tool| self.is_tool_discoverable(tool))
    }

    /// Complete operator-visible tool catalog with owning maturity metadata.
    pub fn catalog_tools_with_modules(
        &self,
    ) -> impl Iterator<Item = (&BuiltinModule, &ToolDescriptor)> {
        self.modules
            .values()
            .filter(|module| !module.is_hidden())
            .flat_map(|module| {
                module
                    .tools()
                    .iter()
                    .filter(|tool| !tool.hidden)
                    .map(move |tool| (module, tool))
            })
    }

    /// Default catalog projection with owning module maturity available to
    /// presentation layers.
    pub fn discoverable_catalog_tools_with_modules(
        &self,
    ) -> impl Iterator<Item = (&BuiltinModule, &ToolDescriptor)> {
        self.catalog_tools_with_modules()
            .filter(|(module, tool)| tool.effective_maturity(module.maturity()).is_core())
    }

    /// Iterate every operator-visible `(module metadata, tool)` pair.
    pub fn tools_with_modules(&self) -> impl Iterator<Item = (&ModuleMetadata, &ToolDescriptor)> {
        self.modules
            .values()
            .filter(|module| !module.is_hidden())
            .flat_map(|module| {
                module
                    .tools()
                    .iter()
                    .filter(|tool| !tool.hidden)
                    .map(move |tool| (module.metadata(), tool))
            })
    }

    /// Iterate visible Core `(module metadata, tool)` pairs for default
    /// catalog grouping and guided queries.
    pub fn discoverable_tools_with_modules(
        &self,
    ) -> impl Iterator<Item = (&ModuleMetadata, &ToolDescriptor)> {
        self.discoverable_catalog_tools_with_modules()
            .map(|(module, tool)| (module.metadata(), tool))
    }

    pub fn resolve_tool(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(name)
    }

    /// Shared discovery policy for guided actions that refer to an exact tool.
    /// Registration alone does not make an internal or research tool a default.
    pub fn tool_is_discoverable(&self, name: &str) -> bool {
        self.resolve_tool(name)
            .is_some_and(|tool| self.is_tool_discoverable(tool))
    }

    /// Whether an input key names a filesystem path in this tool's declared
    /// contract. `target` is deliberately overloaded across Kuzushi: scanners
    /// use a path, while recon/offense tools use the same spelling for a host.
    /// Callers resolving workspace roots must consult the descriptor instead
    /// of guessing from the key name alone.
    pub fn tool_option_is_path(&self, tool_name: &str, option_name: &str) -> bool {
        self.resolve_tool(tool_name).is_some_and(|tool| {
            tool.options.iter().any(|option| {
                option.matches_name_or_alias(option_name) && option.option_type == OptionType::Path
            })
        })
    }

    pub fn tool_needs_runtime(&self, name: &str, input: &Value) -> bool {
        let requirement = self
            .tools
            .get(name)
            .map(|tool| tool.runtime_requirement)
            .unwrap_or(RuntimeRequirement::Never);
        match requirement {
            RuntimeRequirement::Never => false,
            RuntimeRequirement::Always => true,
            RuntimeRequirement::InputAware => input_aware_tool_needs_runtime(name, input),
        }
    }

    pub fn tool_wants_runtime(&self, name: &str, input: &Value, config: &V2Config) -> bool {
        self.tool_needs_runtime(name, input) || tool_optionally_wants_runtime(name, input, config)
    }

    /// Whether a tool is operator-visible, independent of its maturity tier.
    pub(crate) fn is_tool_visible(&self, tool: &ToolDescriptor) -> bool {
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

    fn is_tool_discoverable(&self, tool: &ToolDescriptor) -> bool {
        if !self.is_tool_visible(tool) {
            return false;
        }
        let Some((module_id, _)) = tool.name.split_once(':') else {
            return false;
        };
        self.modules
            .get(module_id)
            .is_some_and(|module| tool.effective_maturity(module.maturity()).is_core())
    }

    fn dynamic_specifier_for_module(&self, module_id: &str) -> Option<String> {
        self.dynamic_tools
            .values()
            .find(|binding| binding.module_id == module_id)
            .map(|binding| binding.specifier.clone())
    }
}
