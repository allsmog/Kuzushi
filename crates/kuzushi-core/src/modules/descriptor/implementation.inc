use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub id: String,
    pub name: String,
    pub kind: ModuleKind,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleKind {
    Offense,
    Intel,
    Governance,
    Defense,
    Internal,
    Catalog,
    Config,
    Context,
    Scan,
    Findings,
    Triage,
    Workspace,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub headless: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionSpec>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OptionType {
    String,
    Bool,
    Int,
    Float,
    Path,
    Enum,
    StringList,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OptionSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub option_type: OptionType,
    pub description: String,
    pub required: bool,
    pub advanced: bool,
    pub evasion: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

impl OptionSpec {
    fn new(name: &str, option_type: OptionType, description: &str) -> Self {
        Self {
            name: name.to_string(),
            option_type,
            description: description.to_string(),
            required: false,
            advanced: false,
            evasion: false,
            default: None,
            choices: Vec::new(),
        }
    }

    pub(in crate::modules) fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub(in crate::modules) fn advanced(mut self) -> Self {
        self.advanced = true;
        self
    }

    pub(in crate::modules) fn evasion(mut self) -> Self {
        self.evasion = true;
        self
    }

    pub(in crate::modules) fn default(mut self, value: Value) -> Self {
        self.default = Some(value);
        self
    }

    pub(in crate::modules) fn choices(mut self, choices: &[&str]) -> Self {
        self.choices = choices.iter().map(|choice| (*choice).to_string()).collect();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagNodeDescriptor {
    pub id: String,
    pub output_kind: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BuiltinModule {
    metadata: ModuleMetadata,
    tools: Vec<ToolDescriptor>,
    dag_nodes: Vec<DagNodeDescriptor>,
    hidden: bool,
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

fn module(
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

pub(in crate::modules) fn max_findings_option(default: usize) -> OptionSpec {
    opt(
        "maxFindings",
        OptionType::Int,
        "Maximum findings or candidates to return.",
    )
    .default(json!(default))
}

pub(in crate::modules) fn fingerprint_option() -> OptionSpec {
    opt(
        "fingerprint",
        OptionType::String,
        "Finding fingerprint or stable finding alias.",
    )
    .required()
}

pub(in crate::modules) fn binary_option(description: &str) -> OptionSpec {
    opt("binary", OptionType::Path, description).advanced()
}

pub(in crate::modules) fn dag(
    id: &str,
    output_kind: &str,
    depends_on: &[&str],
) -> DagNodeDescriptor {
    DagNodeDescriptor {
        id: id.to_string(),
        output_kind: output_kind.to_string(),
        depends_on: depends_on
            .iter()
            .map(|dependency| dependency.to_string())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_visible_and_hidden_modules() {
        let visible = builtin_module(
            "demo",
            "Demo",
            ModuleKind::Defense,
            "Visible module",
            vec![tool("demo:run", "Run demo.")],
            vec![dag("demo:run", "findings", &["context:build"])],
        );
        assert_eq!(visible.metadata().id, "demo");
        assert!(!visible.is_hidden());
        assert_eq!(visible.tools()[0].name, "demo:run");
        assert_eq!(visible.dag_nodes()[0].depends_on, vec!["context:build"]);

        let hidden = hidden_module(
            "internal-demo",
            "Internal Demo",
            ModuleKind::Internal,
            "Hidden module",
            vec![],
            vec![],
        );
        assert!(hidden.is_hidden());
    }

    #[test]
    fn option_builders_set_contract_flags_without_exposing_mutation() {
        let option = opt("mode", OptionType::Enum, "Mode.")
            .required()
            .advanced()
            .evasion()
            .default(json!("auto"))
            .choices(&["auto", "manual"]);

        assert_eq!(option.name, "mode");
        assert!(option.required);
        assert!(option.advanced);
        assert!(option.evasion);
        assert_eq!(option.default, Some(json!("auto")));
        assert_eq!(option.choices, vec!["auto", "manual"]);
    }

    #[test]
    fn common_option_helpers_keep_expected_names_and_types() {
        assert_eq!(target_option().option_type, OptionType::Path);
        assert_eq!(model_option().name, "model");
        assert!(model_option().advanced);
        assert_eq!(max_findings_option(7).default, Some(json!(7)));
        assert!(fingerprint_option().required);
        assert_eq!(binary_option("Binary path.").option_type, OptionType::Path);
    }
}
