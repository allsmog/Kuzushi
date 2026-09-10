use super::{domain::*, persistence::*};
use crate::spend::SpendLimiter;
use anyhow::{Context, Result};
use rusqlite::TransactionBehavior;

impl SpendLimiter {
    /// Inspect persisted accounting without initializing or migrating a ledger.
    pub fn read_allowance_snapshot(path: &std::path::Path, investigation_id: &str) -> Result<AllowanceSnapshot> {
        validate_identifier(investigation_id)?;
        if !path.try_exists()? {
            return Err(AllowanceError::NotApproved(investigation_id.into()).into());
        }
        let mut conn = crate::sqlite_connection::open_read_only_file(path)?;
        let transaction = conn.transaction()?;
        let exists: bool = transaction.query_row(
            "select exists(select 1 from sqlite_master where type = 'table' and name = 'investigation_allowance_revisions')",
            [], |row| row.get(0),
        )?;
        anyhow::ensure!(exists, AllowanceError::NotApproved(investigation_id.into()));
        let snapshot = snapshot(&transaction, investigation_id)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Persist an explicit operator approval with optimistic revision checking.
    /// This does not authorize jobs, transport, or a model change by itself.
    pub fn approve_allowance(&self, approval: &AllowanceApprovalV1) -> Result<AllowanceSnapshot> {
        approval.validate()?;
        let mut state = self.lock();
        let transaction = state.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = latest_approval(&transaction, &approval.investigation_id)?;
        require_revision(approval.expected_revision, current.as_ref().map_or(0, |entry| entry.0))?;
        validate_revised_limits(&transaction, approval)?;
        super::work_admission::preserve_work_plan(&transaction, approval, current.as_ref().map(|entry| &entry.1))?;
        let revision = approval.expected_revision.checked_add(1).context("allowance revision overflow")?;
        insert_approval(&transaction, approval, revision)?;
        let snapshot = snapshot(&transaction, &approval.investigation_id)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub fn allowance_snapshot(&self, investigation_id: &str) -> Result<AllowanceSnapshot> {
        validate_identifier(investigation_id)?;
        let mut state = self.lock();
        let transaction = state.conn.transaction()?;
        let snapshot = snapshot(&transaction, investigation_id)?;
        transaction.commit()?;
        Ok(snapshot)
    }
}

fn validate_revised_limits(conn: &rusqlite::Connection, approval: &AllowanceApprovalV1) -> Result<()> {
    let usage = usage(conn, &approval.investigation_id)?;
    let review_remaining = approval.limits.protected_review_calls.saturating_sub(usage.review);
    let required = usage.calls.checked_add(review_remaining).context("allowance commitment overflow")?;
    anyhow::ensure!(
        approval.limits.max_provider_calls >= required,
        "revised allowance cannot discard committed calls or the protected review allocation"
    );
    Ok(())
}
