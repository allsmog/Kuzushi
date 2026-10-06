//! Durable investigation allowance shared by preparation, discovery and review.
//! Admission reserves a provider attempt before transport starts. Failed and
//! cancelled attempts retain their reservation: an absent receipt is not a refund.
//! This ledger limits calls; it makes no dollar-ceiling or job-approval claim.

mod admission;
mod approval;
mod binding;
mod campaign_binding;
pub use campaign_binding::CampaignAllowanceReport;
mod domain;
pub(super) mod persistence;
mod reference;
mod run_usage;
pub use run_usage::ProviderRunUsage;
mod settlement;
#[cfg(test)]
mod tests;
mod work_admission;
mod work_plan;
#[cfg(test)]
mod work_tests;

pub use binding::{AllowanceBinding, AllowanceWork};
pub use domain::{
    AllowanceApprovalV1, AllowanceCall, AllowanceError, AllowanceLimits, AllowanceReservation,
    AllowanceSnapshot, InvestigationWork,
};
pub use reference::AllowanceReferenceV1;
pub use work_plan::{ApprovedWorkItem, ApprovedWorkPlanV1, WorkAttempt};
