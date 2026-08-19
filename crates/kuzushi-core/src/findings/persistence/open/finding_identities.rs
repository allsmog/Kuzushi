use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::findings::persistence::open) struct FindingIdentityAssignment {
    pub identity_id: String,
    pub match_tier: FindingIdentityMatchTier,
}

/// Bound on how many prior-run rows are inspected for one identity reuse
/// query before giving up and calculating a new structural identity.
const CROSS_RUN_CANDIDATE_LIMIT: usize = 32;

impl FindingStore {
    pub(in crate::findings::persistence::open) fn identity_assignment_for_finding(
        &self,
        conn: &Connection,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<FindingIdentityAssignment> {
        let context = scan_identity_context(conn, scan_id)?;
        // Preserve already-issued identities before applying the structural
        // key used for new findings. Reuse is target-scoped: one FindingStore
        // may contain runs for multiple repositories, and a producer
        // fingerprint or dedup key is not globally unique across those targets.
        if let Some(reused) =
            self.exact_fingerprint_identity(conn, scan_id, &context.target_id, finding)?
        {
            return Ok(reused);
        }
        if let Some(reused) = self.cross_run_identity(conn, scan_id, &context.target_id, finding)? {
            return Ok(reused);
        }
        let identity_key = finding_identity_key_for_finding_at_target(
            finding,
            std::path::Path::new(&context.target_id),
        );
        let identity_id = compute_finding_identity_id(&context.target_id, &identity_key.key);
        let assignment = FindingIdentityAssignment {
            identity_id,
            match_tier: identity_key.match_tier,
        };
        Ok(assignment)
    }

    /// Reuse a prior identity for the exact producer fingerprint before
    /// calculating a key with the new structural algorithm. This keeps legacy
    /// identities traceable for findings that predate dedup-key population.
    fn exact_fingerprint_identity(
        &self,
        conn: &Connection,
        scan_id: &str,
        target_id: &str,
        finding: &Finding,
    ) -> Result<Option<FindingIdentityAssignment>> {
        if finding.fingerprint.trim().is_empty() {
            return Ok(None);
        }
        let rekeyed = rekeyed_old_fps(conn)?;
        let identity_id =
            prior_run_fingerprint_rows(conn, scan_id, target_id, &finding.fingerprint)?
                .into_iter()
                .find(|prior| reusable_exact_fingerprint_identity(prior, finding, &rekeyed))
                .and_then(|prior| prior.identity_id);
        Ok(identity_id.map(|identity_id| FindingIdentityAssignment {
            identity_id,
            match_tier: FindingIdentityMatchTier::StableFingerprint,
        }))
    }

    /// Same dedup_key + same file on an open row from an earlier run of the
    /// same target reuses that row's identity, so repeated hunts converge on
    /// one durable identity instead of minting a fresh `fi_` per
    /// differently-worded rediscovery. Rows are never merged — only the
    /// identity is shared.
    fn cross_run_identity(
        &self,
        conn: &Connection,
        scan_id: &str,
        target_id: &str,
        finding: &Finding,
    ) -> Result<Option<FindingIdentityAssignment>> {
        let Some(dedup_key) = finding.dedup_key.as_deref() else {
            return Ok(None);
        };
        let rekeyed = rekeyed_old_fps(conn)?;
        let identity_id = prior_run_rows(conn, scan_id, target_id, dedup_key)?
            .into_iter()
            .find(|prior| reusable_prior_identity(prior, finding, &rekeyed))
            .and_then(|prior| prior.identity_id);
        Ok(identity_id.map(|identity_id| FindingIdentityAssignment {
            identity_id,
            match_tier: FindingIdentityMatchTier::DedupKeyCrossRun,
        }))
    }
}

fn prior_run_fingerprint_rows(
    conn: &Connection,
    scan_id: &str,
    target_id: &str,
    fingerprint: &str,
) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "select fc.finding_json
           from finding_current fc
           join run_states rs on rs.run_id = fc.run_id
          where fc.fingerprint = ?1
            and fc.run_id <> ?2
            and rs.target = ?3
          order by fc.id asc
          limit ?4",
    )?;
    let rows = stmt
        .query_map(
            params![
                fingerprint,
                scan_id,
                target_id,
                CROSS_RUN_CANDIDATE_LIMIT as i64
            ],
            super::finding_writes::row_to_current_finding,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn prior_run_rows(
    conn: &Connection,
    scan_id: &str,
    target_id: &str,
    dedup_key: &str,
) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "select fc.finding_json
           from finding_current fc
           join run_states rs on rs.run_id = fc.run_id
          where fc.dedup_key = ?1
            and fc.run_id <> ?2
            and rs.target = ?3
          order by fc.id asc
          limit ?4",
    )?;
    let rows = stmt
        .query_map(
            params![
                dedup_key,
                scan_id,
                target_id,
                CROSS_RUN_CANDIDATE_LIMIT as i64
            ],
            super::finding_writes::row_to_current_finding,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn reusable_prior_identity(
    prior: &Finding,
    incoming: &Finding,
    rekeyed_old_fps: &std::collections::HashSet<String>,
) -> bool {
    if prior.identity_id.is_none() || prior.suppressed {
        return false;
    }
    if normalized_identity_file(&prior.file_path) != normalized_identity_file(&incoming.file_path) {
        return false;
    }
    let stable_key = prior
        .identity_id
        .as_deref()
        .unwrap_or(prior.fingerprint.as_str());
    !rekeyed_old_fps.contains(stable_key) && !rekeyed_old_fps.contains(&prior.fingerprint)
}

fn reusable_exact_fingerprint_identity(
    prior: &Finding,
    incoming: &Finding,
    rekeyed_old_fps: &std::collections::HashSet<String>,
) -> bool {
    reusable_prior_identity(prior, incoming, rekeyed_old_fps)
        && normalized_identity_token(&prior.tool) == normalized_identity_token(&incoming.tool)
        && normalized_identity_token(&prior.rule_id) == normalized_identity_token(&incoming.rule_id)
}

fn normalized_identity_file(file_path: &str) -> String {
    crate::identity::finding_identity::normalize_path(file_path)
}

fn normalized_identity_token(value: &str) -> String {
    crate::identity::finding_identity::normalize_token(value)
}

fn rekeyed_old_fps(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare("select old_fp from rekey_edges")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
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
