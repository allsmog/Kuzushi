use kuzushi_mcp_common::ReadRootCapability;

pub(crate) struct HealthTool;
pub(crate) struct ParseTool {
    pub(crate) read_capability: ReadRootCapability,
}

impl ParseTool {
    pub(crate) fn new(read_capability: ReadRootCapability) -> Self {
        Self { read_capability }
    }
}
pub(crate) struct CallersOfTool;
pub(crate) struct CalleesOfTool;
pub(crate) struct DefinitionsTool;
pub(crate) struct CpgSizeTool;
pub(crate) struct ReachingDefTool;
pub(crate) struct TaintPathsTool;
pub(crate) struct UnsafeBlocksTool;
pub(crate) struct FfiBoundariesTool;
pub(crate) struct MethodAtTool;
