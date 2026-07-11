use super::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(in crate::modules) type ToolDispatchResult = Option<Result<Value>>;
pub(in crate::modules) type ToolExecutor = fn(
    &ModuleRegistry,
    &str,
    &Value,
    &ToolExecutionContext<'_>,
    Option<&dyn AgentRuntime>,
) -> Result<Value>;

static NEXT_REGISTRY_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct ModuleRegistry {
    pub(in crate::modules) identity: u64,
    pub(in crate::modules) modules: BTreeMap<String, BuiltinModule>,
    pub(in crate::modules) tools: BTreeMap<String, ToolDescriptor>,
    pub(in crate::modules) executors: BTreeMap<String, ToolExecutor>,
    pub(in crate::modules) dynamic_tools: BTreeMap<String, DynamicToolBinding>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self {
            identity: NEXT_REGISTRY_IDENTITY.fetch_add(1, Ordering::Relaxed),
            modules: BTreeMap::new(),
            tools: BTreeMap::new(),
            executors: BTreeMap::new(),
            dynamic_tools: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct DynamicToolBinding {
    pub(in crate::modules) specifier: String,
    pub(in crate::modules) module_id: String,
    pub(in crate::modules) verified: Option<crate::worker_protocol::VerifiedModule>,
    pub(in crate::modules) lockfile_path: Option<PathBuf>,
    pub(in crate::modules) approval: Option<crate::worker_protocol::LockfileEntry>,
    pub(in crate::modules) _bundle_snapshot: Option<Arc<tempfile::TempDir>>,
}
