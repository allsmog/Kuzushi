use super::prelude::*;
use super::*;

#[derive(Debug, Clone)]
pub struct BuiltinModule {
    pub(in crate::modules) metadata: ModuleMetadata,
    pub(in crate::modules) tools: Vec<ToolDescriptor>,
    pub(in crate::modules) dag_nodes: Vec<DagNodeDescriptor>,
    pub(in crate::modules) hidden: bool,
}

impl BuiltinModule {
    pub fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }

    pub fn tools(&self) -> &[ToolDescriptor] {
        &self.tools
    }

    pub fn dag_nodes(&self) -> &[DagNodeDescriptor] {
        &self.dag_nodes
    }

    pub fn is_hidden(&self) -> bool {
        self.hidden
    }
}

pub(in crate::modules) fn builtin_module(
    id: &str,
    name: &str,
    kind: ModuleKind,
    description: &str,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
) -> BuiltinModule {
    module(id, name, kind, description, tools, dag_nodes, false)
}

pub(in crate::modules) fn hidden_module(
    id: &str,
    name: &str,
    kind: ModuleKind,
    description: &str,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
) -> BuiltinModule {
    module(id, name, kind, description, tools, dag_nodes, true)
}

pub(in crate::modules) fn module(
    id: &str,
    name: &str,
    kind: ModuleKind,
    description: &str,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
    hidden: bool,
) -> BuiltinModule {
    BuiltinModule {
        metadata: ModuleMetadata {
            id: id.to_string(),
            name: name.to_string(),
            kind,
            description: description.to_string(),
        },
        tools,
        dag_nodes,
        hidden,
    }
}

pub(in crate::modules) fn tool(name: &str, description: &str) -> ToolDescriptor {
    tool_with_options(name, description, vec![])
}

pub(in crate::modules) fn tool_with_options(
    name: &str,
    description: &str,
    options: Vec<OptionSpec>,
) -> ToolDescriptor {
    ToolDescriptor {
        name: name.to_string(),
        description: description.to_string(),
        headless: true,
        options,
    }
}

pub(in crate::modules) fn opt(
    name: &str,
    option_type: OptionType,
    description: &str,
) -> OptionSpec {
    OptionSpec::new(name, option_type, description)
}

pub(in crate::modules) fn target_option() -> OptionSpec {
    opt(
        "target",
        OptionType::Path,
        "Repository or workspace path; defaults to the active workspace when supported.",
    )
}

pub(in crate::modules) fn model_option() -> OptionSpec {
    opt(
        "model",
        OptionType::String,
        "Explicit provider:model override for this tool run.",
    )
    .advanced()
}
