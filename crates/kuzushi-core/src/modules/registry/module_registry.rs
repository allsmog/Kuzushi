use super::*;

pub(in crate::modules) type ToolDispatchResult = Option<Result<Value>>;
pub(in crate::modules) type ToolExecutor = fn(
    &ModuleRegistry,
    &str,
    &Value,
    &ToolExecutionContext<'_>,
    Option<&dyn AgentRuntime>,
) -> Result<Value>;

#[derive(Debug, Default, Clone)]
pub struct ModuleRegistry {
    pub(in crate::modules) modules: BTreeMap<String, BuiltinModule>,
    pub(in crate::modules) tools: BTreeMap<String, ToolDescriptor>,
    pub(in crate::modules) executors: BTreeMap<String, ToolExecutor>,
    pub(in crate::modules) dynamic_tools: BTreeMap<String, DynamicToolBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::modules) struct DynamicToolBinding {
    pub(in crate::modules) specifier: String,
    pub(in crate::modules) module_id: String,
}
