use super::prelude::*;
use super::*;

pub(in crate::modules) type ToolDispatchResult = Option<Result<Value>>;

#[derive(Debug, Default, Clone)]
pub struct ModuleRegistry {
    pub(in crate::modules) modules: BTreeMap<String, BuiltinModule>,
    pub(in crate::modules) tools: BTreeMap<String, ToolDescriptor>,
}
