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
        upsert_identity(conn, &context, finding, &assignment)?;
        record_identity_fingerprint(conn, &assignment, &finding.fingerprint, &finding.created_at)?;
        Ok(assignment)
    }

    pub(in crate::findings::persistence::open) fn record_collision_identity(
        &self,
        conn: &Connection,
        existing: &Finding,
        incoming: &Finding,
    ) -> Result<()> {
        let Some(identity_id) = existing.identity_id.as_deref() else {
            return Ok(());
        };
        let assignment = FindingIdentityAssignment {
            identity_id: identity_id.to_string(),
            match_tier: FindingIdentityMatchTier::DedupCollision,
        };
        record_identity_fingerprint(
            conn,
            &assignment,
            &incoming.fingerprint,
            &incoming.created_at,
        )
    }
}

struct ScanIdentityContext {
    scan_id: String,
    target_id: String,
    started_at: String,
}

fn scan_identity_context(conn: &Connection, scan_id: &str) -> Result<ScanIdentityContext> {
    conn.query_row(
        "select run_id, target, updated_at from run_states where run_id = ?1",
        params![scan_id],
        |row| {
            Ok(ScanIdentityContext {
                scan_id: row.get(0)?,
                target_id: row.get(1)?,
                started_at: row.get(2)?,
            })
        },
    )
    .with_context(|| format!("scan run {scan_id:?} is required before finding identity assignment"))
}

fn upsert_identity(
    conn: &Connection,
    context: &ScanIdentityContext,
    finding: &Finding,
    assignment: &FindingIdentityAssignment,
) -> Result<()> {
    let created_at = identity_created_at(&finding.created_at, &context.started_at);
    insert_identity(
        conn,
        context,
        &assignment.identity_id,
        &finding.fingerprint,
        created_at,
    )
}

fn insert_identity(
    conn: &Connection,
    context: &ScanIdentityContext,
    identity_id: &str,
    fingerprint: &str,
    created_at: &str,
) -> Result<()> {
    conn.execute(
        r#"
        insert into finding_identities(
          identity_id, target_id, alias, fingerprint_current,
          first_seen_run_id, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6)
        on conflict(identity_id) do nothing
        "#,
        params![
            identity_id,
            context.target_id,
            finding_identity_alias(identity_id),
            fingerprint,
            context.scan_id,
            created_at,
        ],
    )?;
    Ok(())
}

fn record_identity_fingerprint(
    conn: &Connection,
    assignment: &FindingIdentityAssignment,
    fingerprint: &str,
    created_at: &str,
) -> Result<()> {
    conn.execute(
        r#"
        insert or ignore into finding_identity_fingerprints(
          identity_id, fingerprint, match_basis, created_at
        )
        values (?1, ?2, ?3, ?4)
        "#,
        params![
            assignment.identity_id,
            fingerprint,
            assignment.match_tier.as_str(),
            created_at
        ],
    )?;
    Ok(())
}

fn identity_created_at<'a>(finding_created_at: &'a str, run_started_at: &'a str) -> &'a str {
    if finding_created_at.trim().is_empty() {
        run_started_at
    } else {
        finding_created_at
    }
}
