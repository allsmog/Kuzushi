use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::findings::persistence::open) struct FindingIdentityAssignment {
    pub identity_id: String,
    pub match_tier: FindingIdentityMatchTier,
}

impl FindingStore {
    pub(in crate::findings::persistence::open) fn identity_assignment_for_finding(
        &self,
        conn: &Connection,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<FindingIdentityAssignment> {
        let context = scan_identity_context(conn, scan_id)?;
        let identity_key = finding_identity_key_for_finding(finding);
        let identity_id = compute_finding_identity_id(&context.target_id, &identity_key.key);
        let assignment = FindingIdentityAssignment {
            identity_id,
            match_tier: identity_key.match_tier,
        };
        Ok(assignment)
    }
}

struct ScanIdentityContext {
    target_id: String,
}

fn scan_identity_context(conn: &Connection, scan_id: &str) -> Result<ScanIdentityContext> {
    conn.query_row(
        "select target from run_states where run_id = ?1",
        params![scan_id],
        |row| {
            Ok(ScanIdentityContext {
                target_id: row.get(0)?,
            })
        },
    )
    .with_context(|| format!("scan run {scan_id:?} is required before finding identity assignment"))
}
