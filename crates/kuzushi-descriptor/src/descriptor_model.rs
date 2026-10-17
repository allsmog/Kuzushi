use crate::{
    ApprovalPolicy, FindingStoreRequirement, ModuleMaturity, ToolEffect, ToolPhase, ToolPolicy,
    WorkspaceRequirement,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
mod tests;

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
    /// A tool can further restrict its owning module's discovery tier.
    #[serde(
        default,
        rename = "discoveryMaturity",
        skip_serializing_if = "Option::is_none"
    )]
    pub discovery_maturity: Option<ModuleMaturity>,
    /// Runtime-free readers may project historical spend inside their payload.
    #[serde(
        default,
        rename = "costDataProjection",
        skip_serializing_if = "is_false"
    )]
    pub cost_data_projection: bool,
    #[serde(default, skip_serializing_if = "RuntimeRequirement::is_never")]
    pub runtime_requirement: RuntimeRequirement,
    /// How a failed run of this tool can be continued. Declarative so the
    /// planner, result card, and `resume` know without executing the tool.
    /// `skip_serializing_if` keeps descriptor fingerprints stable for
    /// non-adopting tools.
    #[serde(default, skip_serializing_if = "ContinuationSupport::is_none")]
    pub continuation: ContinuationSupport,
    /// Canonical journey phase for grouping. Always serialized so `tools --json`
    /// is explicit; `#[serde(default)]` keeps old manifests/dynamic modules
    /// (which land in OPERATE) deserializable.
    #[serde(default)]
    pub phase: ToolPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowance_category: Option<AllowanceCategory>,
    /// Whether this tool can contribute a selectable phase result. This is
    /// independent of its authorization phase and effect. Omission preserves
    /// existing descriptors and their serialized identities.
    #[serde(default = "default_phase_result", skip_serializing_if = "is_true")]
    pub phase_result: bool,
    #[serde(default)]
    pub effect: ToolEffect,
    #[serde(default)]
    pub approval: ApprovalPolicy,
    #[serde(default)]
    pub workspace_requirement: WorkspaceRequirement,
    #[serde(default)]
    pub finding_store_requirement: FindingStoreRequirement,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionSpec>,
    /// Operator-reviewable instruction templates used by model-backed tools.
    /// Runtime-generated repository context is intentionally not represented
    /// here: this is the stable, editable instruction surface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<PromptSpec>,
    /// Descriptor-authoring state; excluded from serialization and identity.
    #[doc(hidden)]
    #[serde(skip)]
    pub policy_declared: bool,
}

impl PartialEq for ToolDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.description == other.description
            && self.headless == other.headless
            && self.hidden == other.hidden
            && self.discovery_maturity == other.discovery_maturity
            && self.cost_data_projection == other.cost_data_projection
            && self.runtime_requirement == other.runtime_requirement
            && self.continuation == other.continuation
            && self.phase == other.phase
            && self.allowance_category == other.allowance_category
            && self.phase_result == other.phase_result
            && self.effect == other.effect
            && self.approval == other.approval
            && self.workspace_requirement == other.workspace_requirement
            && self.finding_store_requirement == other.finding_store_requirement
            && self.options == other.options
            && self.prompts == other.prompts
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AllowanceCategory {
    Context,
    Scope,
    Discovery,
    Review,
    Report,
    Learning,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PromptSpec {
    pub role: String,
    pub module_id: String,
    pub verb: String,
    pub option_key: String,
    pub default_content: String,
    pub context_note: String,
}

impl PromptSpec {
    pub fn override_relative_path(&self) -> std::path::PathBuf {
        crate::prompt_paths::relative_prompt_override_path(&self.module_id, &self.verb)
    }
}

fn default_phase_result() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
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

/// How a failed run of a tool can be continued after re-dispatch of the
/// same tool + input.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ContinuationSupport {
    /// Re-dispatch restarts the tool from scratch.
    #[default]
    None,
    /// The shared agent tool loop's transcript checkpoint resumes completed
    /// turns automatically on identical re-dispatch.
    Loop,
    /// The tool consumes a `StageCheckpointHandle` and skips stages whose
    /// receipts (and artifacts) survive from the failed run.
    Staged,
}

impl ContinuationSupport {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Whether an identical re-dispatch can pick up prior paid work.
    pub fn is_continuable(&self) -> bool {
        !self.is_none()
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
    /// Opts operator-authored JSON into the generic settings editor.
    /// Workflow references remain read-only when this flag is omitted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub editable_json: bool,
    /// Required for `type = path`; describes containment and provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_semantics: Option<PathSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_reference_semantics: Option<FileReferenceSemantics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deprecated_aliases: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PathSemantics {
    WorkspaceRead,
    StateWrite,
    TargetWrite,
    ExternalRead,
    ExternalWrite,
    Executable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FileReferenceSemantics {
    InlineOrWorkspaceFile,
    InlineOrWorkspaceFiles,
}

impl PathSemantics {
    pub fn forbids_workspace_storage(self) -> bool {
        !matches!(self, Self::WorkspaceRead)
    }
}

/// Descriptor-authoring internals used by Kuzushi's registration layer.
#[doc(hidden)]
impl OptionSpec {
    pub fn new(name: &str, option_type: OptionType, description: &str) -> Self {
        Self {
            name: name.to_string(),
            option_type,
            description: description.to_string(),
            required: false,
            advanced: false,
            evasion: false,
            editable_json: false,
            path_semantics: None,
            file_reference_semantics: None,
            default: None,
            minimum: None,
            maximum: None,
            choices: Vec::new(),
            aliases: Vec::new(),
            deprecated_aliases: Vec::new(),
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn advanced(mut self) -> Self {
        self.advanced = true;
        self
    }

    pub fn editable_json(mut self) -> Self {
        self.editable_json = true;
        self
    }

    pub fn evasion(mut self) -> Self {
        self.evasion = true;
        self
    }

    pub fn workspace_read(mut self) -> Self {
        self.path_semantics = Some(PathSemantics::WorkspaceRead);
        self
    }

    pub fn state_write(mut self) -> Self {
        self.path_semantics = Some(PathSemantics::StateWrite);
        self
    }

    pub fn target_write(mut self) -> Self {
        self.path_semantics = Some(PathSemantics::TargetWrite);
        self
    }

    pub fn external_write(mut self) -> Self {
        self.path_semantics = Some(PathSemantics::ExternalWrite);
        self
    }

    pub fn external_read(mut self) -> Self {
        self.path_semantics = Some(PathSemantics::ExternalRead);
        self
    }

    pub fn executable(mut self) -> Self {
        self.path_semantics = Some(PathSemantics::Executable);
        self
    }

    pub fn inline_or_workspace_file(mut self) -> Self {
        self.file_reference_semantics = Some(FileReferenceSemantics::InlineOrWorkspaceFile);
        self
    }

    pub fn inline_or_workspace_files(mut self) -> Self {
        self.file_reference_semantics = Some(FileReferenceSemantics::InlineOrWorkspaceFiles);
        self
    }

    pub fn default(mut self, value: Value) -> Self {
        self.default = Some(value);
        self
    }

    pub fn integer_range(mut self, minimum: i64, maximum: i64) -> Self {
        self.minimum = Some(minimum);
        self.maximum = Some(maximum);
        self
    }

    pub fn choices(mut self, choices: &[&str]) -> Self {
        self.choices = choices.iter().map(|choice| (*choice).to_string()).collect();
        self
    }

    pub fn aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(|alias| (*alias).to_string()).collect();
        self
    }

    pub fn deprecated_aliases(mut self, aliases: &[&str]) -> Self {
        self.deprecated_aliases = aliases.iter().map(|alias| (*alias).to_string()).collect();
        self
    }
}

impl OptionSpec {
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
}

impl PartialEq for DagNodeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.output_kind == other.output_kind
            && self.depends_on == other.depends_on
    }
}

impl Eq for DagNodeDescriptor {}

/// Descriptor-authoring internals used by Kuzushi's registration layer.
#[doc(hidden)]
impl ToolDescriptor {
    pub fn with_cost_data_projection(mut self) -> Self {
        self.cost_data_projection = true;
        self
    }
    pub fn with_discovery_maturity(mut self, maturity: ModuleMaturity) -> Self {
        self.discovery_maturity = Some(maturity);
        self
    }

    /// Tool metadata cannot promote an experimental or compatibility module.
    pub fn effective_maturity(&self, owner: ModuleMaturity) -> ModuleMaturity {
        if owner.is_core() {
            return self.discovery_maturity.unwrap_or(owner);
        }
        owner
    }

    pub fn with_allowance_category(mut self, category: AllowanceCategory) -> Self {
        self.allowance_category = Some(category);
        self
    }
    pub fn with_prompt(mut self, prompt: PromptSpec) -> Self {
        self.prompts.push(prompt);
        self
    }

    pub fn without_phase_result(mut self) -> Self {
        self.phase_result = false;
        self
    }

    pub fn with_continuation(mut self, continuation: ContinuationSupport) -> Self {
        self.continuation = continuation;
        self
    }

    pub fn with_policy(mut self, policy: ToolPolicy) -> Self {
        self.phase = policy.phase;
        self.runtime_requirement = policy.runtime_requirement;
        self.effect = policy.effect;
        self.approval = policy.approval;
        self.workspace_requirement = policy.workspace_requirement;
        self.finding_store_requirement = policy.finding_store_requirement;
        self.policy_declared = true;
        self
    }
}
