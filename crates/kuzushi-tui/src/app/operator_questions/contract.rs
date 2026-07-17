use super::credential_policy::question_requests_credentials;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) const REQUEST_USER_INPUT_TOOL: &str =
    kuzushi_core::runtime::REQUEST_USER_INPUT_TOOL_NAME;
pub(crate) const MAX_QUESTION_CALLS: usize = 3;
pub(crate) const MAX_AGENT_STEPS: u32 = 8;
const MIN_AUTO_RESOLUTION_MS: u64 = 60_000;
const MAX_AUTO_RESOLUTION_MS: u64 = 240_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OperatorQuestionOption {
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OperatorQuestion {
    pub id: String,
    pub header: String,
    #[serde(alias = "question")]
    pub prompt: String,
    pub options: Vec<OperatorQuestionOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct OperatorQuestionRequest {
    pub request_id: String,
    pub run_id: String,
    pub questions: Vec<OperatorQuestion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_resolution_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct OperatorQuestionInput {
    questions: Vec<OperatorQuestion>,
    #[serde(default)]
    auto_resolution_ms: Option<u64>,
}

impl OperatorQuestionRequest {
    pub(crate) fn from_tool_input(run_id: &str, input: Value) -> Result<Self> {
        let input: OperatorQuestionInput =
            serde_json::from_value(input).context("request_user_input received invalid input")?;
        let request = Self {
            request_id: format!("question-{}", uuid::Uuid::new_v4().simple()),
            run_id: run_id.to_string(),
            questions: input.questions,
            auto_resolution_ms: input.auto_resolution_ms,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=3).contains(&self.questions.len()),
            "request_user_input requires 1 to 3 questions"
        );
        validate_auto_resolution(self.auto_resolution_ms)?;
        validate_questions(&self.questions)
    }

    pub(crate) fn recommended_resolution(&self) -> OperatorQuestionResolution {
        OperatorQuestionResolution {
            request_id: self.request_id.clone(),
            kind: OperatorQuestionResolutionKind::AutoResolved,
            answers: self
                .questions
                .iter()
                .enumerate()
                .map(|(ordinal, question)| recommended_answer(&self.request_id, ordinal, question))
                .collect(),
        }
    }

    /// Credential collection is never delegated to the model-owned question
    /// card. The root shell redirects these requests to Setup/Auth, where
    /// secret entry stays in the dedicated masked credential surface.
    pub(crate) fn requires_credential_route(&self) -> bool {
        self.questions.iter().any(question_requests_credentials)
    }
}

fn validate_auto_resolution(value: Option<u64>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    anyhow::ensure!(
        (MIN_AUTO_RESOLUTION_MS..=MAX_AUTO_RESOLUTION_MS).contains(&value),
        "auto_resolution_ms must be between 60000 and 240000"
    );
    Ok(())
}

fn validate_questions(questions: &[OperatorQuestion]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for question in questions {
        validate_question(question)?;
        anyhow::ensure!(
            ids.insert(question.id.as_str()),
            "request_user_input question ids must be unique"
        );
    }
    Ok(())
}

fn validate_question(question: &OperatorQuestion) -> Result<()> {
    anyhow::ensure!(
        !question.id.trim().is_empty(),
        "question id must not be empty"
    );
    anyhow::ensure!(
        !question.header.trim().is_empty() && question.header.chars().count() <= 12,
        "question header must contain 1 to 12 characters"
    );
    anyhow::ensure!(
        !question.prompt.trim().is_empty(),
        "question prompt must not be empty"
    );
    anyhow::ensure!(
        (2..=3).contains(&question.options.len()),
        "each question requires 2 or 3 predefined options"
    );
    validate_options(&question.options)
}

fn validate_options(options: &[OperatorQuestionOption]) -> Result<()> {
    anyhow::ensure!(
        options.iter().filter(|option| option.recommended).count() == 1,
        "each question requires exactly one recommended option"
    );
    for option in options {
        anyhow::ensure!(
            !option.label.trim().is_empty(),
            "option label must not be empty"
        );
        anyhow::ensure!(
            !option.description.trim().is_empty(),
            "option description must not be empty"
        );
    }
    Ok(())
}

fn recommended_answer(
    request_id: &str,
    question_ordinal: usize,
    question: &OperatorQuestion,
) -> OperatorQuestionAnswer {
    let (choice_ordinal, option) = question
        .options
        .iter()
        .enumerate()
        .find(|(_, option)| option.recommended)
        .expect("checked question has a recommendation");
    OperatorQuestionAnswer::Predefined {
        question_id: question.id.clone(),
        choice_id: kuzushi_core::run_lifecycle::deterministic_choice_id(
            request_id,
            &question.id,
            question_ordinal,
            choice_ordinal,
        )
        .to_string(),
        label: option.label.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum OperatorQuestionAnswer {
    Predefined {
        question_id: String,
        choice_id: String,
        label: String,
    },
    Freeform {
        question_id: String,
        text: String,
    },
}

impl OperatorQuestionAnswer {
    pub(crate) fn question_id(&self) -> &str {
        match self {
            Self::Predefined { question_id, .. } | Self::Freeform { question_id, .. } => {
                question_id
            }
        }
    }

    pub(crate) fn predefined_label(&self) -> Option<&str> {
        match self {
            Self::Predefined { label, .. } => Some(label),
            Self::Freeform { .. } => None,
        }
    }

    pub(crate) fn is_freeform(&self) -> bool {
        matches!(self, Self::Freeform { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperatorQuestionResolutionKind {
    Submitted,
    Canceled,
    AutoResolved,
    RoutedToSetup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorQuestionOutcome {
    Submitted,
    AutoResolved,
    Canceled,
    RoutedToSetup,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorQuestionCompleted {
    pub request_id: String,
    pub run_id: String,
    pub outcome: OperatorQuestionOutcome,
    pub selected_labels: Vec<String>,
    pub freeform_supplied: bool,
}

impl OperatorQuestionCompleted {
    pub(crate) fn from_resolution(run_id: &str, resolution: &OperatorQuestionResolution) -> Self {
        Self {
            request_id: resolution.request_id.clone(),
            run_id: run_id.to_string(),
            outcome: match resolution.kind {
                OperatorQuestionResolutionKind::Submitted => OperatorQuestionOutcome::Submitted,
                OperatorQuestionResolutionKind::Canceled => OperatorQuestionOutcome::Canceled,
                OperatorQuestionResolutionKind::AutoResolved => {
                    OperatorQuestionOutcome::AutoResolved
                }
                OperatorQuestionResolutionKind::RoutedToSetup => {
                    OperatorQuestionOutcome::RoutedToSetup
                }
            },
            selected_labels: resolution
                .answers
                .iter()
                .filter_map(OperatorQuestionAnswer::predefined_label)
                .map(str::to_string)
                .collect(),
            freeform_supplied: resolution
                .answers
                .iter()
                .any(OperatorQuestionAnswer::is_freeform),
        }
    }

    pub(crate) fn failed(request: &OperatorQuestionRequest) -> Self {
        Self {
            request_id: request.request_id.clone(),
            run_id: request.run_id.clone(),
            outcome: OperatorQuestionOutcome::Failed,
            selected_labels: Vec::new(),
            freeform_supplied: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OperatorQuestionResolution {
    pub request_id: String,
    pub kind: OperatorQuestionResolutionKind,
    pub answers: Vec<OperatorQuestionAnswer>,
}

impl OperatorQuestionResolution {
    pub(crate) fn canceled(request_id: String) -> Self {
        Self {
            request_id,
            kind: OperatorQuestionResolutionKind::Canceled,
            answers: Vec::new(),
        }
    }

    pub(crate) fn routed_to_setup(request_id: String) -> Self {
        Self {
            request_id,
            kind: OperatorQuestionResolutionKind::RoutedToSetup,
            answers: Vec::new(),
        }
    }
}

pub(crate) fn request_user_input_tool() -> kuzushi_core::runtime::AgentTool {
    kuzushi_core::runtime::AgentTool {
        name: REQUEST_USER_INPUT_TOOL.to_string(),
        description: "Pause for 1-3 concise operator choices when the answer materially changes the work. Other is added by the shell.".to_string(),
        input_schema: request_schema(),
    }
}

fn request_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["questions"],
        "properties": {
            "questions": question_array_schema(),
            "auto_resolution_ms": timeout_schema()
        }
    })
}

fn question_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 3,
        "items": question_schema()
    })
}

fn question_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "header", "prompt", "options"],
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "header": {"type": "string", "minLength": 1, "maxLength": 12},
            "prompt": {"type": "string", "minLength": 1},
            "options": option_array_schema()
        }
    })
}

fn option_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 2,
        "maxItems": 3,
        "items": option_schema()
    })
}

fn option_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["label", "description", "recommended"],
        "properties": {
            "label": {"type": "string", "minLength": 1},
            "description": {"type": "string", "minLength": 1},
            "recommended": {"type": "boolean"}
        }
    })
}

fn timeout_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": MIN_AUTO_RESOLUTION_MS,
        "maximum": MAX_AUTO_RESOLUTION_MS
    })
}
