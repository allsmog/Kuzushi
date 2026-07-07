use super::*;
use crate::modules::registry::ToolExecutor;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub headless: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "RuntimeRequirement::is_never")]
    pub runtime_requirement: RuntimeRequirement,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionSpec>,
    #[serde(skip)]
    pub(in crate::modules) executor: Option<ToolExecutor>,
}

impl PartialEq for ToolDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.description == other.description
            && self.headless == other.headless
            && self.hidden == other.hidden
            && self.runtime_requirement == other.runtime_requirement
            && self.options == other.options
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeRequirement {
    #[default]
    Never,
    Always,
    InputAware,
}

impl RuntimeRequirement {
    pub fn is_never(&self) -> bool {
        matches!(self, Self::Never)
    }
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
    Json,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deprecated_aliases: Vec<String>,
}

impl OptionSpec {
    pub(in crate::modules) fn new(name: &str, option_type: OptionType, description: &str) -> Self {
        Self {
            name: name.to_string(),
            option_type,
            description: description.to_string(),
            required: false,
            advanced: false,
            evasion: false,
            default: None,
            choices: Vec::new(),
            aliases: Vec::new(),
            deprecated_aliases: Vec::new(),
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

    pub(in crate::modules) fn aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(|alias| (*alias).to_string()).collect();
        self
    }

    pub(in crate::modules) fn deprecated_aliases(mut self, aliases: &[&str]) -> Self {
        self.deprecated_aliases = aliases.iter().map(|alias| (*alias).to_string()).collect();
        self
    }

    pub fn matches_name_or_alias(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
            || self
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
            || self
                .deprecated_aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNodeDescriptor {
    pub id: String,
    pub output_kind: String,
    pub depends_on: Vec<String>,
    #[serde(skip)]
    pub(in crate::modules) executor: Option<ToolExecutor>,
}

impl PartialEq for DagNodeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.output_kind == other.output_kind
            && self.depends_on == other.depends_on
    }
}

impl Eq for DagNodeDescriptor {}
