use super::*;
use crate::modules::runtime_requirements::input_aware_tool_needs_runtime;
use crate::modules::runtime_requirements::tool_optionally_wants_runtime;
use crate::V2Config;

impl ModuleRegistry {
    pub fn tool_requires_finding_store(&self, name: &str) -> bool {
        self.resolve_tool(name).is_some_and(|tool| {
            tool.finding_store_requirement == FindingStoreRequirement::Required
        })
    }

    pub fn tool_requires_workspace(&self, name: &str) -> bool {
        self.resolve_tool(name)
            .is_some_and(|tool| tool.workspace_requirement == WorkspaceRequirement::Required)
    }

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

    /// Iterate visible `(module, tool)` pairs for catalog grouping and querying.
    /// Skips hidden tools and tools whose owning module is hidden.
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

    pub fn resolve_tool(&self, name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(name)
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

    /// Visible to callers that need the same hidden-tool/hidden-module policy
    /// outside the catalog iterators above (e.g. recents bookkeeping at the
    /// dispatch boundary in `execution.rs`).
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

    fn dynamic_specifier_for_module(&self, module_id: &str) -> Option<String> {
        self.dynamic_tools
            .values()
            .find(|binding| binding.module_id == module_id)
            .map(|binding| binding.specifier.clone())
    }
}
