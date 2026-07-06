use super::*;

pub(in crate::findings::persistence::open) struct V3FindingTarget {
    pub event_log_dir: PathBuf,
    pub db_path: PathBuf,
    pub stable_fp: String,
    pub fingerprint: String,
    pub identity_id: Option<String>,
}

impl FindingStore {
    pub(in crate::findings::persistence::open) fn v3_target_for_finding(
        &self,
        finding_id: i64,
        context: &str,
    ) -> Result<Option<V3FindingTarget>> {
        let Some((event_log_dir, db_path)) = self.v3_storage_paths() else {
            return Ok(None);
        };
        let Some(identity) = self.finding_identity_for_id(finding_id, context)? else {
            return Ok(None);
        };
        Ok(Some(V3FindingTarget {
            event_log_dir,
            db_path,
            stable_fp: identity.stable_fp(),
            fingerprint: identity.fingerprint,
            identity_id: identity.identity_id,
        }))
    }

    pub(in crate::findings::persistence::open) fn v3_target_for_fingerprint(
        &self,
        fingerprint: &str,
        context: &str,
    ) -> Result<Option<V3FindingTarget>> {
        let Some((event_log_dir, db_path)) = self.v3_storage_paths() else {
            return Ok(None);
        };
        let identity = self
            .finding_identity_for_fingerprint(fingerprint, context)?
            .unwrap_or_else(|| V3IdentityRef {
                fingerprint: fingerprint.to_string(),
                identity_id: None,
            });
        Ok(Some(V3FindingTarget {
            event_log_dir,
            db_path,
            stable_fp: identity.stable_fp(),
            fingerprint: identity.fingerprint,
            identity_id: identity.identity_id,
        }))
    }

    pub(in crate::findings::persistence::open) fn v3_storage_paths(
        &self,
    ) -> Option<(PathBuf, PathBuf)> {
        Some((self.event_log_dir.clone()?, self.db_path.clone()?))
    }

    pub(in crate::findings::persistence::open) fn finding_identity_for_id(
        &self,
        finding_id: i64,
        context: &str,
    ) -> Result<Option<V3IdentityRef>> {
        self.conn
            .query_row(
                "select fingerprint, identity_id from finding_projection_rows where id = ?1",
                params![finding_id],
                |row| {
                    Ok(V3IdentityRef {
                        fingerprint: row.get(0)?,
                        identity_id: row.get(1)?,
                    })
                },
            )
            .optional()
            .with_context(|| format!("Could not load finding identity for v3 {context}"))
    }

    fn finding_identity_for_fingerprint(
        &self,
        fingerprint: &str,
        context: &str,
    ) -> Result<Option<V3IdentityRef>> {
        self.conn
            .query_row(
                r#"
                select fingerprint, identity_id
                  from finding_projection_rows
                 where fingerprint = ?1
                 order by id desc
                 limit 1
                "#,
                params![fingerprint],
                |row| {
                    Ok(V3IdentityRef {
                        fingerprint: row.get(0)?,
                        identity_id: row.get(1)?,
                    })
                },
            )
            .optional()
            .with_context(|| format!("Could not load finding identity for v3 {context}"))
    }
}

pub(in crate::findings::persistence::open) struct V3IdentityRef {
    pub fingerprint: String,
    pub identity_id: Option<String>,
}

impl V3IdentityRef {
    pub(in crate::findings::persistence::open) fn stable_fp(&self) -> String {
        self.identity_id
            .clone()
            .unwrap_or_else(|| self.fingerprint.clone())
    }
}

pub(in crate::findings::persistence::open) fn cost_usd_to_micros(cost_usd: f64) -> i64 {
    if !cost_usd.is_finite() || cost_usd <= 0.0 {
        return 0;
    }
    let micros = cost_usd * 1_000_000.0;
    if micros >= i64::MAX as f64 {
        i64::MAX
    } else {
        micros.round() as i64
    }
}
