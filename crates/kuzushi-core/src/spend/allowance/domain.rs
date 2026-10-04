use crate::runtime::RuntimeCostReport;
use anyhow::Result;
use serde::{Deserialize, Serialize};

const MAX_PROVIDER_CALLS: u32 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceLimits {
    pub max_provider_calls: u32,
    pub protected_review_calls: u32,
}

impl AllowanceLimits {
    pub(super) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=MAX_PROVIDER_CALLS).contains(&self.max_provider_calls),
            "provider call limit must be between 1 and {MAX_PROVIDER_CALLS}"
        );
        anyhow::ensure!(
            self.protected_review_calls <= self.max_provider_calls,
            "protected review calls must fit within the total allowance"
        );
        Ok(())
    }
}

/// Written only after an operator accepts these exact limits. A revision changes
/// the investigation's total allowance; it does not reset consumed reservations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceApprovalV1 {
    pub schema_version: u32,
    pub investigation_id: String,
    pub expected_revision: u32,
    pub model: String,
    pub limits: AllowanceLimits,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_plan: Option<super::ApprovedWorkPlanV1>,
}

impl AllowanceApprovalV1 {
    pub(super) fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.schema_version == 1, "unsupported allowance approval version");
        validate_identifier(&self.investigation_id)?;
        validate_text(&self.model, "explicit allowance model", 256)?;
        validate_text(&self.reason, "allowance approval reason", 4096)?;
        if let Some(plan) = &self.work_plan { plan.validate()?; }
        self.limits.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationWork {
    Context,
    Scope,
    Discovery,
    Review,
    Report,
    Learning,
}

impl InvestigationWork {
    pub(super) fn is_review(self) -> bool {
        matches!(self, Self::Review | Self::Report)
    }
}

/// One potential billable request, including each retry and internal model turn.
/// `request_id` must be fresh for each attempt. Reusing it never grants transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceCall {
    pub investigation_id: String,
    pub expected_revision: u32,
    pub request_id: String,
    pub run_id: String,
    pub work_id: String,
    pub model: String,
    pub work: InvestigationWork,
}

impl AllowanceCall {
    pub(super) fn validate(&self) -> Result<()> {
        for value in [&self.investigation_id, &self.request_id, &self.run_id, &self.work_id] {
            validate_identifier(value)?;
        }
        validate_text(&self.model, "explicit request model", 256)
    }
}

/// Reservation identity is minted by the ledger, never accepted from a model.
#[derive(Debug)]
pub struct AllowanceReservation {
    pub(super) ledger_id: String,
    pub(super) investigation_id: String,
    pub(super) request_id: String,
    pub(super) reservation_id: String,
}

impl AllowanceReservation {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceSnapshot {
    pub schema_version: u32,
    pub investigation_id: String,
    pub revision: u32,
    pub model: String,
    pub limits: AllowanceLimits,
    pub committed_calls: u32,
    pub review_calls: u32,
    pub unresolved_calls: u32,
    pub cost: RuntimeCostReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_plan: Option<super::ApprovedWorkPlanV1>,
}

impl AllowanceSnapshot {
    pub fn remaining_calls(&self) -> u32 {
        self.limits.max_provider_calls.saturating_sub(self.committed_calls)
    }

    pub fn protected_review_remaining(&self) -> u32 {
        self.limits.protected_review_calls.saturating_sub(self.review_calls)
    }

    pub fn remaining_discovery_calls(&self) -> u32 {
        self.remaining_calls().saturating_sub(self.protected_review_remaining())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AllowanceError {
    #[error("investigation {0:?} has no approved allowance")]
    NotApproved(String),
    #[error("allowance revision changed: expected {expected}, current {current}; review remaining work")]
    StaleRevision { expected: u32, current: u32 },
    #[error("allowance exhausted: {committed} calls committed, limit {limit}, {protected} reserved for review; finish and report or approve revised work")]
    Exhausted { committed: u32, limit: u32, protected: u32 },
    #[error("request {0:?} was already reserved; a retry requires a new reservation")]
    AlreadyReserved(String),
    #[error("request model differs from the approved allowance model")]
    ModelMismatch,
}

pub(super) fn validate_identifier(value: &str) -> Result<()> {
    validate_text(value, "allowance identity", 128)?;
    anyhow::ensure!(
        value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)),
        "allowance identities accept only letters, digits, dot, underscore, colon and dash"
    );
    Ok(())
}

fn validate_text(value: &str, label: &str, maximum: usize) -> Result<()> {
    anyhow::ensure!(!value.is_empty() && value.len() <= maximum, "invalid {label} length");
    anyhow::ensure!(value.trim() == value && !value.chars().any(char::is_control), "invalid {label}");
    Ok(())
}
