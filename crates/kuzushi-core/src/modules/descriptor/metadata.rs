use super::descriptor_validation::validate_declared_policy;
use super::*;
use crate::modules::registry::ToolExecutor;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct BuiltinModule {
    pub(in crate::modules) metadata: ModuleMetadata,
    pub(in crate::modules) tools: Vec<ToolDescriptor>,
    pub(in crate::modules) dag_nodes: Vec<DagNodeDescriptor>,
    pub(in crate::modules) tool_executors: BTreeMap<String, ToolExecutor>,
    pub(in crate::modules) dag_executors: BTreeMap<String, ToolExecutor>,
    pub(in crate::modules) hidden: bool,
    pub(in crate::modules) maturity: ModuleMaturity,
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

    pub fn maturity(&self) -> ModuleMaturity {
        self.maturity
    }

    pub(in crate::modules) fn deferred(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// Mark an explicitly callable module as a research capability. Labs
    /// modules remain registered for exact dispatch but are omitted from the
    /// default catalog and guided surfaces.
    pub(in crate::modules) fn labs(mut self) -> Self {
        self.maturity = ModuleMaturity::Labs;
        self
    }

    /// Mark an explicitly callable module as a retained migration/integration
    /// surface rather than the recommended product path.
    pub(in crate::modules) fn compatibility(mut self) -> Self {
        self.maturity = ModuleMaturity::Compatibility;
        self
    }

    pub(in crate::modules) fn with_executor(mut self, executor: ToolExecutor) -> Self {
        for tool in &self.tools {
            self.tool_executors.insert(tool.name.clone(), executor);
        }
        for node in &self.dag_nodes {
            self.dag_executors.insert(node.id.clone(), executor);
        }
        self
    }

    pub(in crate::modules) fn with_tool_executor(
        mut self,
        name: &str,
        executor: ToolExecutor,
    ) -> Self {
        debug_assert!(
            self.tools.iter().any(|tool| tool.name == name),
            "with_tool_executor: no tool named {name:?}"
        );
        self.tool_executors.insert(name.to_string(), executor);
        self
    }

    pub(in crate::modules) fn validate_declared_policy(&self) -> Result<()> {
        for tool in &self.tools {
            validate_declared_policy(tool, &self.metadata.id)?;
        }
        Ok(())
    }
}

pub(in crate::modules) fn tools_with_policy(
    policy: ToolPolicy,
    tools: Vec<ToolDescriptor>,
) -> Vec<ToolDescriptor> {
    tools
        .into_iter()
        .map(|tool| tool.with_policy(policy))
        .collect()
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
        tool_executors: BTreeMap::new(),
        dag_executors: BTreeMap::new(),
        hidden,
        maturity: ModuleMaturity::Core,
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
        hidden: false,
        runtime_requirement: RuntimeRequirement::Never,
        continuation: ContinuationSupport::None,
        phase: ToolPhase::default(),
        phase_result: true,
        effect: ToolEffect::default(),
        approval: ApprovalPolicy::default(),
        workspace_requirement: WorkspaceRequirement::default(),
        finding_store_requirement: FindingStoreRequirement::default(),
        options,
        prompts: Vec::new(),
        policy_declared: false,
    }
}

pub(in crate::modules) fn editable_prompt(
    role: &str,
    module_id: &str,
    verb: &str,
    option_key: &str,
    default_content: String,
) -> PromptSpec {
    PromptSpec {
        role: role.to_string(),
        module_id: module_id.to_string(),
        verb: verb.to_string(),
        option_key: option_key.to_string(),
        default_content,
        context_note: "Repository context is generated at runtime and is not part of this editable instruction template.".to_string(),
    }
}

pub(in crate::modules) fn hidden_tool_with_options(
    name: &str,
    description: &str,
    options: Vec<OptionSpec>,
) -> ToolDescriptor {
    let mut descriptor = tool_with_options(name, description, options);
    descriptor.hidden = true;
    descriptor
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
    .aliases(&["cwd"])
    .workspace_read()
}

pub(in crate::modules) fn model_option() -> OptionSpec {
    opt(
        "model",
        OptionType::String,
        "Explicit provider:model override for this tool run.",
    )
    .advanced()
}
