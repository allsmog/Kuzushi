use super::*;
use crate::modules::registry::ToolExecutor;

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

    pub(in crate::modules) fn deferred(mut self) -> Self {
        self.hidden = true;
        self
    }

    pub(in crate::modules) fn with_executor(mut self, executor: ToolExecutor) -> Self {
        for tool in &mut self.tools {
            tool.executor = Some(executor);
        }
        for node in &mut self.dag_nodes {
            node.executor = Some(executor);
        }
        self
    }

    pub(in crate::modules) fn validate_declared_policy(&self) -> Result<()> {
        for tool in &self.tools {
            tool.validate_declared_policy(&self.metadata.id)?;
        }
        Ok(())
    }
}

impl ToolDescriptor {
    pub(in crate::modules) fn with_prompt(mut self, prompt: PromptSpec) -> Self {
        self.prompts.push(prompt);
        self
    }

    pub(in crate::modules) fn with_policy(mut self, policy: ToolPolicy) -> Self {
        self.phase = policy.phase;
        self.runtime_requirement = policy.runtime_requirement;
        self.effect = policy.effect;
        self.approval = policy.approval;
        self.workspace_requirement = policy.workspace_requirement;
        self.finding_store_requirement = policy.finding_store_requirement;
        self.policy_declared = true;
        self
    }

    fn validate_declared_policy(&self, module_id: &str) -> Result<()> {
        if !self.policy_declared {
            anyhow::bail!(
                "built-in tool {:?} in module {:?} has no descriptor-owned policy",
                self.name,
                module_id
            )
        }
        if self.effect.needs_operator_approval() && self.approval != ApprovalPolicy::Explicit {
            anyhow::bail!(
                "built-in tool {:?} has {:?} effect without explicit approval",
                self.name,
                self.effect
            )
        }
        if self.finding_store_requirement == FindingStoreRequirement::Required
            && self.workspace_requirement != WorkspaceRequirement::Required
        {
            anyhow::bail!(
                "built-in tool {:?} requires a finding store but not a workspace",
                self.name
            )
        }
        self.validate_prompt_options("built-in tool")?;
        Ok(())
    }

    pub(in crate::modules) fn validate_prompt_options(&self, kind: &str) -> Result<()> {
        for prompt in &self.prompts {
            if !self
                .options
                .iter()
                .any(|option| option.name == prompt.option_key)
            {
                anyhow::bail!(
                    "{kind} {:?} prompt {:?} refers to undeclared option {:?}",
                    self.name,
                    prompt.role,
                    prompt.option_key
                )
            }
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
        hidden,
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
        phase: ToolPhase::default(),
        effect: ToolEffect::default(),
        approval: ApprovalPolicy::default(),
        workspace_requirement: WorkspaceRequirement::default(),
        finding_store_requirement: FindingStoreRequirement::default(),
        options,
        prompts: Vec::new(),
        executor: None,
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
